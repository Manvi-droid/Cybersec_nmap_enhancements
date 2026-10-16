local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Passively maps a web site from a single request. The script fetches only the base
page (one GET, redirects are not followed) and reports what the page itself reveals,
without requesting any of the paths it finds:

* Form targets: where each form submits (method and action), whether the target is
  on another host, and whether the form contains a password field.
* Script sources and external hosts: scripts, stylesheets, frames and images loaded
  from other hosts, and local script paths.
* Paths and URLs mentioned in HTML comments.
* Internal links found on the page (listed, not requested).
* Technology hints from the Server and X-Powered-By headers and the generator meta tag.

Because it never guesses paths, it sends one request, which looks like an ordinary
page view. Compare with http-enum, which sends thousands of fingerprint requests.
The script only sees what the site serves to this client; sites that cloak their
content may show a different page to scanners.
]]

---
-- @usage
-- nmap -p 80,8080 --script http-passive-map <target>
-- nmap -p 8080 --script http-passive-map --script-args http-passive-map.basepath=/app/ <target>
--
-- @args http-passive-map.basepath  Page to fetch. Default: /
-- @args http-passive-map.maxitems  Maximum entries listed per section. Default: 40.
-- @args http.useragent             (standard http library argument) Set a browser-like
--                                  User-Agent to blend in with normal visitors.
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-passive-map:
-- |   Technology:
-- |     Server: SimpleHTTP/0.6 Python/3.12
-- |   Forms:
-- |     POST /x7f92/login (password field)
-- |     POST http://collect.example.net/post.php (password field; external host)
-- |   Comment hints:
-- |     /old-admin/
-- |   Script sources:
-- |     http://cdn.example.net/lib.js (external)
-- |   External hosts:
-- |     collect.example.net (form)
-- |     cdn.example.net (script)
-- |_  Requests sent: 1

author = "Manvi Sharma"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function tag_attr(tag, name)
  local pat = "%s" .. (name:gsub("%a", function (c) return "[" .. c:lower() .. c:upper() .. "]" end))
  return tag:match(pat .. "%s*=%s*\"([^\"]*)\"")
    or tag:match(pat .. "%s*=%s*'([^']*)'")
    or tag:match(pat .. "%s*=%s*([^%s>]+)")
end

local function same_host(host, link_host)
  link_host = link_host:lower()
  local names = { host.ip, host.name, host.targetname, stdnse.get_hostname(host) }
  for _, n in ipairs(names) do
    if n and n ~= "" and link_host == tostring(n):lower() then
      return true
    end
  end
  return false
end

---Classify a link. Returns "internal", path  or  "external", hostname, full_url  or nil.
local function resolve(link, host, dir)
  link = link:match("^%s*(.-)%s*$")
  if link == "" then return nil end
  local l = link:lower()
  if l:find("^#") or l:find("^mailto:") or l:find("^javascript:")
    or l:find("^tel:") or l:find("^data:") then
    return nil
  end

  local lhost, rest = link:match("^%a[%w+.-]*://([^/?#]*)(.*)$")
  if not lhost then
    lhost, rest = link:match("^//([^/?#]*)(.*)$")
  end
  if lhost then
    lhost = lhost:gsub("^.*@", "")
    lhost = lhost:gsub(":%d+$", "")
    if same_host(host, lhost) then
      local p = rest:match("^([^?#]*)")
      if p == "" then p = "/" end
      return "internal", p
    end
    return "external", lhost:lower(), link
  elseif link:find("^%a[%w+.-]*:") then
    return nil -- some other scheme
  end

  local path = link:match("^([^?#]*)")
  if path == "" then return nil end
  if path:sub(1, 1) ~= "/" then
    path = dir .. (path:gsub("^%./", ""))
  end
  return "internal", path
end

local function new_list(max)
  return { items = {}, seen = {}, max = max, dropped = 0 }
end

local function add(list, value)
  if list.seen[value] then return end
  list.seen[value] = true
  if #list.items < list.max then
    list.items[#list.items + 1] = value
  else
    list.dropped = list.dropped + 1
  end
end

local function finish(list)
  if list.dropped > 0 then
    list.items[#list.items + 1] = string.format("(+%d more)", list.dropped)
  end
  return list.items
end

local COMMENT_KEEP_EXT = { php = true, asp = true, aspx = true, jsp = true, cgi = true,
  bak = true, old = true, sql = true, zip = true, txt = true, xml = true, json = true,
  html = true, htm = true, js = true, conf = true, cfg = true, log = true }

---Pull paths and URLs out of the text of an HTML comment.
local function comment_tokens(text)
  local found = {}
  for tok in text:gmatch("[^%s\"'`()<>,;=]+") do
    tok = tok:gsub("[%.:]+$", "")
    if tok:find("^https?://") or tok:find("^//[%w%-]+%.") then
      found[#found + 1] = tok
    elseif tok:find("^/[%w_%-%.~]") then
      found[#found + 1] = tok
    else
      local ext = tok:match("^[%w_%-%./]+%.(%w+)$")
      if ext and COMMENT_KEEP_EXT[ext:lower()] then
        found[#found + 1] = tok
      end
    end
  end
  return found
end

action = function(host, port)
  local basepath = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or "/"
  local max = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxitems")) or 40
  if basepath:sub(1, 1) ~= "/" then basepath = "/" .. basepath end
  local dir = basepath:match("^(.*/)") or "/"

  local res = http.get(host, port, basepath, { redirect_ok = false })
  if not res or not res.status then return nil end

  local out = stdnse.output_table()

  if res.status >= 300 and res.status < 400 then
    local loc = res.header and res.header.location
    if loc then
      out["Redirect"] = string.format("%s -> %s (not followed)", basepath, loc)
      out["Requests sent"] = 1
      return out
    end
    return nil
  end
  if res.status ~= 200 or not res.body or #res.body == 0 then return nil end

  local body = res.body:sub(1, 262144)

  -- Technology hints
  local tech = {}
  if res.header then
    if res.header["server"] then tech[#tech + 1] = "Server: " .. res.header["server"] end
    if res.header["x-powered-by"] then tech[#tech + 1] = "X-Powered-By: " .. res.header["x-powered-by"] end
  end

  -- Comments: collect hints, then remove them so they are not parsed as markup
  local comments = new_list(max)
  for c in body:gmatch("<!%-%-(.-)%-%->") do
    for _, tok in ipairs(comment_tokens(c)) do add(comments, tok) end
  end
  local markup = body:gsub("<!%-%-.-%-%->", "")

  -- Individual tags
  local scripts, internal, frames = new_list(max), new_list(max), new_list(max)
  local ext_hosts, ext_order = {}, {}
  local function note_host(h, kind)
    if not ext_hosts[h] then
      ext_hosts[h] = { kinds = {}, order = {} }
      ext_order[#ext_order + 1] = h
    end
    local e = ext_hosts[h]
    if not e.kinds[kind] then
      e.kinds[kind] = true
      e.order[#e.order + 1] = kind
    end
  end

  for tag in markup:gmatch("<[^>]+>") do
    local name = tag:match("^<%s*(%a[%w]*)")
    name = name and name:lower()
    local attr, kind
    if name == "script" then attr, kind = "src", "script"
    elseif name == "link" then attr, kind = "href", "stylesheet/link"
    elseif name == "iframe" or name == "frame" then attr, kind = "src", "frame"
    elseif name == "img" then attr, kind = "src", "image"
    elseif name == "a" then attr, kind = "href", "link"
    elseif name == "meta" then
      local mname = tag_attr(tag, "name")
      if mname and mname:lower() == "generator" then
        local content = tag_attr(tag, "content")
        if content then tech[#tech + 1] = "Generator: " .. content end
      end
    end

    local value = attr and tag_attr(tag, attr)
    if value then
      local where, a, b = resolve(value, host, dir)
      if where == "external" then
        note_host(a, kind)
        if kind == "script" then add(scripts, b .. " (external)") end
        if kind == "frame" then add(frames, b .. " (external)") end
      elseif where == "internal" then
        if kind == "script" then add(scripts, a .. " (local)")
        elseif kind == "frame" then add(frames, a)
        elseif kind == "link" then add(internal, a)
        end
      end
    end
  end

  -- Forms: need the enclosing block to look for password fields
  local forms = new_list(max)
  local lower = markup:lower()
  local pos = 1
  while true do
    local s = lower:find("<form[%s>]", pos)
    if not s then break end
    local tag_end = lower:find(">", s, true) or #lower
    local close = lower:find("</form", tag_end, true) or #lower
    local tag = markup:sub(s, tag_end)
    local inner = lower:sub(tag_end, close)
    local method = (tag_attr(tag, "method") or "get"):upper()
    local action_attr = tag_attr(tag, "action")
    local target, notes = nil, {}
    if not action_attr or action_attr:match("^%s*$") then
      target = "(same page)"
    else
      local where, a, b = resolve(action_attr, host, dir)
      if where == "external" then
        target = b
        notes[#notes + 1] = "external host"
        note_host(a, "form")
      elseif where == "internal" then
        target = a
        add(internal, a)
      else
        target = action_attr
      end
    end
    if inner:find("<input[^>]-type%s*=%s*[\"']?password") then
      table.insert(notes, 1, "password field")
    end
    local line = method .. " " .. target
    if #notes > 0 then line = line .. " (" .. table.concat(notes, "; ") .. ")" end
    add(forms, line)
    pos = close + 1
    if pos > #lower then break end
  end

  local hosts_out = {}
  for _, h in ipairs(ext_order) do
    hosts_out[#hosts_out + 1] = string.format("%s (%s)", h, table.concat(ext_hosts[h].order, ", "))
  end

  if #tech > 0 then out["Technology"] = tech end
  if #forms.items > 0 then out["Forms"] = finish(forms) end
  if #comments.items > 0 then out["Comment hints"] = finish(comments) end
  if #scripts.items > 0 then out["Script sources"] = finish(scripts) end
  if #frames.items > 0 then out["Embedded frames"] = finish(frames) end
  if #hosts_out > 0 then out["External hosts"] = hosts_out end
  if #internal.items > 0 then out["Internal paths (not requested)"] = finish(internal) end
  out["Requests sent"] = 1

  return out
end
