local base64 = require "base64"
local datafiles = require "datafiles"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

local openssl = stdnse.silent_require "openssl"

description = [[
Gets the favicon ("favorites icon") from a web page and matches it against a
database of the icons of known web applications. If there is a match, the name
of the application is printed; otherwise the MD5 hash of the icon data is
printed.

Enhancements: (1) The MurmurHash3 value of the icon, computed the way Shodan
computes <code>http.favicon.hash</code>, is shown next to the MD5 so the same
icon can be searched for on other hosts. (2) A <code><link></code> favicon that
points to a different host or port is no longer silently dropped: its URL is
reported (it is not requested). (3) A relative <code><link></code> favicon on a
non-default port is now requested from the scanned port; before, it was looked up
on port 80 and discarded. The hash and external-icon lines are only added with
<code>-v</code> or when <code>favicon.details</code> is true, so default output is
unchanged.

If the script argument <code>favicon.uri</code> is given, that relative URI is
always used to find the favicon. Otherwise, first the page at the root of the
web server is retrieved and parsed for a <code><link rel="icon"></code>
element. If that fails, the icon is looked for in <code>/favicon.ico</code>. If
a <code><link></code> favicon points to a different host or port, it is not
requested.
]]

---
-- @args favicon.uri URI that will be requested for favicon.
-- @args favicon.root Web server path to search for favicon.
-- @args favicon.details Set to true to show the MurmurHash3 value and any externally
--       hosted icon without -v (they are otherwise shown only with -v). Default: false.
--
-- @usage
-- nmap --script=http-favicon.nse \
--    --script-args favicon.root=<root>,favicon.uri=<uri>
-- @output
-- |_ http-favicon: Socialtext
--
-- With -v (or favicon.details=true), an unrecognised icon also gets its MurmurHash3:
-- | http-favicon:
-- |   Unknown favicon MD5: B345F9AFABD7D3A4299453ACF59ED4CD
-- |_  MurmurHash3 (Shodan http.favicon.hash): -1131268418
--
-- An icon linked from another host is reported but not requested:
-- |_http-favicon: Favicon linked from external host (not requested): http://cdn.example.net/favicon.ico

-- HTTP default favicon enumeration script
-- rev 1.2 (2009-03-11)
-- Original NASL script by Javier Fernandez-Sanguino Pena


author = "Vlatko Kosturjak"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

-- Extra detail lines (MurmurHash3, external icon) appear with -v or favicon.details.
function verbose_details()
  local arg = stdnse.get_script_args("favicon.details")
  if arg ~= nil then
    arg = tostring(arg):lower()
    if arg == "true" or arg == "1" or arg == "yes" then return true end
    if arg == "false" or arg == "0" or arg == "no" then return false end
  end
  return nmap.verbosity() > 1
end

-- 32-bit MurmurHash3 (x86 variant, seed 0), returned as a signed integer.
local function mmh3_32(data)
  local c1, c2 = 0xcc9e2d51, 0x1b873593
  local h1 = 0
  local len = #data
  local nblocks = len // 4
  local function rotl(x, r) return ((x << r) | (x >> (32 - r))) & 0xffffffff end
  for i = 0, nblocks - 1 do
    local k1 = string.unpack("<I4", data, i * 4 + 1)
    k1 = (k1 * c1) & 0xffffffff
    k1 = rotl(k1, 15)
    k1 = (k1 * c2) & 0xffffffff
    h1 = h1 ~ k1
    h1 = rotl(h1, 13)
    h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
  end
  local k1 = 0
  local tail = len & 3
  local base = nblocks * 4
  if tail >= 3 then k1 = k1 ~ (data:byte(base + 3) << 16) end
  if tail >= 2 then k1 = k1 ~ (data:byte(base + 2) << 8) end
  if tail >= 1 then
    k1 = k1 ~ data:byte(base + 1)
    k1 = (k1 * c1) & 0xffffffff
    k1 = rotl(k1, 15)
    k1 = (k1 * c2) & 0xffffffff
    h1 = h1 ~ k1
  end
  h1 = h1 ~ len
  h1 = h1 ~ (h1 >> 16)
  h1 = (h1 * 0x85ebca6b) & 0xffffffff
  h1 = h1 ~ (h1 >> 13)
  h1 = (h1 * 0xc2b2ae35) & 0xffffffff
  h1 = h1 ~ (h1 >> 16)
  if h1 >= 0x80000000 then h1 = h1 - 0x100000000 end
  return h1
end

-- Hash of the icon in the form used by Shodan's http.favicon.hash: MurmurHash3
-- of the base64 text, wrapped at 76 characters with a trailing newline (the
-- output of Python's base64.encodebytes).
function favicon_mmh3(body)
  local b64 = base64.enc(body)
  local lines = {}
  for i = 1, #b64, 76 do
    lines[#lines + 1] = b64:sub(i, i + 75) .. "\n"
  end
  return mmh3_32(table.concat(lines))
end

action = function(host, port)
  local md5sum,answer
  local match
  local status, favicondb
  local result
  local favicondbfile="nselib/data/favicon-db"
  local index, icon
  local external_icon
  local root = ""
  local details = verbose_details()

  status, favicondb = datafiles.parse_file( favicondbfile, {["^%s*([^%s#:]+)[%s:]+"] = "^%s*[^%s#:]+[%s:]+(.*)"})
  if not status then
    stdnse.debug1("Could not open file: %s", favicondbfile )
    return
  end

  if(stdnse.get_script_args('favicon.root')) then
    root = stdnse.get_script_args('favicon.root')
  end
  local favicon_uri = stdnse.get_script_args("favicon.uri")
  if(favicon_uri) then
    -- If we got a script arg URI, always use that.
    answer = http.get( host, port, root .. "/" .. favicon_uri)
    stdnse.debug4("Using URI %s", favicon_uri)
  else
    -- Otherwise, first try parsing the home page.
    index = http.get( host, port, root .. "/" )
    if index.status == 200 or index.status == 503 then
      -- find the favicon pattern
      icon = parseIcon( index.body )
      -- if we find a pattern
      if icon then
        local hostname = host.targetname or (host.name ~= "" and host.name) or host.ip
        stdnse.debug1("Got icon URL %s.", icon)
        local icon_host, icon_port, icon_path = parse_url_relative(icon, hostname, port.number, root)
        if (icon_host == host.ip or
          icon_host == host.targetname or
          icon_host == (host.name ~= '' and host.name)) and
          icon_port == port.number then
          -- request the favicon
          answer = http.get( icon_host, icon_port, icon_path )
        else
          -- Report the externally hosted icon instead of dropping it silently.
          -- It is not requested, so no third-party host is contacted.
          external_icon = icon
          answer = nil
        end
      else
        answer = nil
      end
    end

    -- If that didn't work, try /favicon.ico.
    if not answer or answer.status ~= 200 then
      answer = http.get( host, port, root .. "/favicon.ico" )
      stdnse.debug4("Using default URI.")
    end
  end

  --- check for 200 response code
  if answer and answer.status == 200 then
    md5sum=string.upper(stdnse.tohex(openssl.md5(answer.body)))
    match=favicondb[md5sum]
    local lines = {}
    if match then
      lines[#lines + 1] = match
    elseif nmap.verbosity() > 0 then
      lines[#lines + 1] = "Unknown favicon MD5: " .. md5sum
    end
    if details then
      lines[#lines + 1] = "MurmurHash3 (Shodan http.favicon.hash): " .. favicon_mmh3(answer.body)
    end
    if external_icon and details then
      lines[#lines + 1] = "Favicon linked from external host (not requested): " .. external_icon
    end
    if #lines == 1 then
      result = lines[1]
    elseif #lines > 1 then
      result = lines
    end
  elseif external_icon and details then
    -- No usable icon on the scanned host, but the page points to one elsewhere.
    result = "Favicon linked from external host (not requested): " .. external_icon
  else
    stdnse.debug1("No favicon found.")
    return
  end --- status == 200
  return result
end

local function dirname(path)
  local dir
  dir = string.match(path, "^(.*)/")
  return dir or ""
end

-- Return a URL's host, port, and path, filling in the results with the given
-- host, port, and path if the URL is relative. Return nil if the scheme is not
-- "http" or "https".
function parse_url_relative(u, host, port, path)
  local scheme, abspath
  u = url.parse(u)
  scheme = u.scheme or "http"
  if not (scheme == "http" or scheme == "https") then
    return nil
  end
  abspath = u.path or ""
  if not string.find(abspath, "^/") then
    abspath = dirname(path) .. "/" .. abspath
  end
  -- A relative URL (no host) stays on the scanned port; only an absolute URL
  -- without an explicit port falls back to the scheme's default port.
  return u.host or host, u.port or (u.host and url.get_default_port(scheme) or port), abspath
end

function parseIcon( body )
  local _, i, j
  local rel, href, word

  -- Loop through link elements.
  i = 0
  while i do
    _, i = string.find(body, "<%s*[Ll][Ii][Nn][Kk]%s", i + 1)
    if not i then
      return nil
    end
    -- Loop through attributes.
    j = i
    while true do
      local name, quote, value
      _, j, name, quote, value = string.find(body, "^%s*(%w+)%s*=%s*([\"'])(.-)%2", j + 1)
      if not j then
        break
      end
      if string.lower(name) == "rel" then
        rel = value
      elseif string.lower(name) == "href" then
        href = value
      end
    end
    for word in string.gmatch(rel or "", "%S+") do
      if string.lower(word) == "icon" then
        return href
      end
    end
  end
end
