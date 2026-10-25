-- doorlock.lua  --  single-file ComputerCraft door lock (v2)
--
-- ONE file for everything. Copy it to every computer as startup.lua and set
-- ROLE below:
--   "server"    the computer with the card database / admin console / dashboard
--   "client"    a door computer (reader + redstone)
--   "nfc_probe" run by hand next to an NFC reader to list its Lua methods
--
-- Edit only the CONFIG blocks directly below. Everything after the line
-- "END OF CONFIGURATION" is code and normally needs no changes.

local ROLE = "client"   -- "server" | "client" | "nfc_probe"

------------------------------------------------------------------------
-- SERVER CONFIG (used when ROLE = "server")
------------------------------------------------------------------------
local SERVER_CONFIG = {
  adminPassword = "",      -- REQUIRED: password for the admin console
  channel       = 74,      -- must match the clients
  readers       = { "disk", "nfc" },
  monitor       = nil,     -- nil = auto-detect, false = none, "monitor_3" = specific
  monitorScale  = 0.5,
  dbFile        = "cards.db",
  logFile       = "access.log",
  maxLog        = 200,     -- entries kept in memory for the dashboard
  unlockSeconds = 120,     -- admin console auto-locks after this much inactivity
  nonceTTL      = 30,      -- seconds a request nonce is remembered (replay protection)
}

------------------------------------------------------------------------
-- CLIENT CONFIG (used when ROLE = "client")
------------------------------------------------------------------------
local CLIENT_CONFIG = {
  doorId        = "",        -- door ID created on the server
  secret        = "",        -- that door's key (shown once on the server)
  title         = "SECURE DOOR",

  redstoneSide  = "left",    -- side that drives the door
  openTime      = 5,         -- seconds the door stays open
  defaultOutput = false,     -- redstone state while locked (true = power cut to unlock)

  lamps = { granted = nil, denied = nil }, -- optional redstone sides for indicator lamps
                                           -- (must differ from redstoneSide)

  readers      = { "disk", "nfc" }, -- which reader types to use
  monitor      = nil,       -- nil = auto-detect, false = none, "monitor_3" = specific
  monitorScale = 1,         -- text scale for the monitor
  channel      = 74,        -- must match the server
  timeout      = 3,         -- seconds to wait for the server
}

------------------------------------------------------------------------
-- END OF CONFIGURATION
------------------------------------------------------------------------

-- Tiny module system so the libraries can live inside this one file.
local __mods, __cache = {}, {}
local function __require(name)
  if __cache[name] == nil then __cache[name] = __mods[name]() end
  return __cache[name]
end

__mods["lib.sha2"] = function()
-- lib/sha2.lua
-- SHA-256, HMAC-SHA256, constant-time compare and an entropy-mixing RNG
-- for CC:Tweaked (Lua 5.1 + bit32).
--
-- Based on the SHA-256 core used in MCJack123's door lock. Fixed here: the
-- original padding added an extra zero block when (len + 9) % 64 == 0, which
-- produced non-standard hashes for 55-byte (mod 64) messages.

local band, bxor, bor, bnot = bit32.band, bit32.bxor, bit32.bor, bit32.bnot
local rshift, lshift = bit32.rshift, bit32.lshift

local M = {}
local MOD = 2 ^ 32

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function rrot(x, n)
  return bor(rshift(x, n), lshift(x, 32 - n))
end

-- big-endian integer -> n-byte string
local function num2s(l, n)
  local s = ""
  for _ = 1, n do
    local rem = l % 256
    s = string.char(rem) .. s
    l = (l - rem) / 256
  end
  return s
end

local function s2num(s, i)
  local a, b, c, d = s:byte(i, i + 3)
  return ((a * 256 + b) * 256 + c) * 256 + d
end

local function compress(msg, i, H)
  local w = {}
  for j = 1, 16 do w[j] = s2num(msg, i + (j - 1) * 4) end
  for j = 17, 64 do
    local v = w[j - 15]
    local s0 = bxor(rrot(v, 7), rrot(v, 18), rshift(v, 3))
    v = w[j - 2]
    local s1 = bxor(rrot(v, 17), rrot(v, 19), rshift(v, 10))
    w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % MOD
  end

  local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
  for j = 1, 64 do
    local S1 = bxor(rrot(e, 6), rrot(e, 11), rrot(e, 25))
    local ch = bxor(band(e, f), band(bnot(e), g))
    local t1 = (h + S1 + ch + K[j] + w[j]) % MOD
    local S0 = bxor(rrot(a, 2), rrot(a, 13), rrot(a, 22))
    local maj = bxor(band(a, b), band(a, c), band(b, c))
    local t2 = (S0 + maj) % MOD
    h, g, f, e, d, c, b, a = g, f, e, (d + t1) % MOD, c, b, a, (t1 + t2) % MOD
  end

  H[1] = (H[1] + a) % MOD; H[2] = (H[2] + b) % MOD
  H[3] = (H[3] + c) % MOD; H[4] = (H[4] + d) % MOD
  H[5] = (H[5] + e) % MOD; H[6] = (H[6] + f) % MOD
  H[7] = (H[7] + g) % MOD; H[8] = (H[8] + h) % MOD
end

--- Raw 32-byte SHA-256 digest.
function M.digest(msg)
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. num2s(len * 8, 8)
  local H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  }
  for i = 1, #msg, 64 do compress(msg, i, H) end
  local out = {}
  for i = 1, 8 do out[i] = num2s(H[i], 4) end
  return table.concat(out)
end

function M.tohex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

--- Hex SHA-256.
function M.hex(msg) return M.tohex(M.digest(msg)) end

--- Raw HMAC-SHA256.
function M.hmacBin(key, msg)
  if #key > 64 then key = M.digest(key) end
  key = key .. string.rep("\0", 64 - #key)
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local kb = key:byte(i)
    ipad[i] = string.char(bxor(kb, 0x36))
    opad[i] = string.char(bxor(kb, 0x5c))
  end
  return M.digest(table.concat(opad) .. M.digest(table.concat(ipad) .. msg))
end

--- Hex HMAC-SHA256.
function M.hmac(key, msg) return M.tohex(M.hmacBin(key, msg)) end

--- Constant-time string comparison.
function M.equals(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do diff = bor(diff, bxor(a:byte(i), b:byte(i))) end
  return diff == 0
end

-- Entropy pool: chained SHA-256 over several unpredictable-ish sources.
-- Much better than raw math.random, but still not a hardware CSPRNG.
local pool = ""
function M.random(n)
  local out, got = {}, 0
  while got < n do
    pool = M.digest(pool
      .. tostring(math.random())
      .. tostring(math.random(0, 2 ^ 31 - 1))
      .. tostring(os.epoch("utc"))
      .. tostring(os.clock())
      .. tostring({})
      .. tostring(os.getComputerID()))
    out[#out + 1] = pool
    got = got + 32
  end
  return table.concat(out):sub(1, n)
end

--- Verifies the implementation against known vectors; errors on mismatch.
function M.selftest()
  local vectors = {
    { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { string.rep("a", 3), "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0" },
    { string.rep("a", 55), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
    { string.rep("a", 56), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a" },
    { string.rep("a", 64), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
  }
  for _, v in ipairs(vectors) do
    if M.hex(v[1]) ~= v[2] then
      error("SHA-256 self-test failed for input of length " .. #v[1], 0)
    end
  end
  if M.hmac("key", "The quick brown fox jumps over the lazy dog")
      ~= "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" then
    error("HMAC-SHA256 self-test failed", 0)
  end
  if M.hmac(string.rep("k", 100), "msg")
      ~= "bd56a1782c2830e8abc6ed866a57a1230661e650b84c62f7ee3accc5fa5af491" then
    error("HMAC-SHA256 long-key self-test failed", 0)
  end
  return true
end

return M

end

__mods["lib.proto"] = function()
-- lib/proto.lua
-- Wire protocol shared by client and server.
--
-- Request  (client -> server): the card ID itself is NEVER transmitted.
--   fp  = short fingerprint of the card ID (lookup key only)
--   mac = HMAC(doorSecret, "req|door|ts|nonce|fp|cardId")  -- proves possession
-- Response (server -> client): signed with the same door secret and bound to
--   the request nonce, so it can't be forged or replayed against another swipe.

local sha2 = __require("lib.sha2")

local proto = {}

proto.VERSION = "CCL2"
proto.DEFAULT_CHANNEL = 74
proto.MAX_SKEW = 10 -- seconds of allowed clock difference

proto.REASONS = {
  unknown_card  = "Card not recognised",
  bad_proof     = "Card failed verification",
  disabled      = "Card has been suspended",
  expired       = "Card has expired",
  no_uses       = "No uses remaining",
  wrong_door    = "Card not valid for this door",
  stale         = "Request expired (clock mismatch)",
  server_error  = "Server error - try again",
  invalid_card  = "Unreadable card",
  no_response   = "Server did not respond",
  bad_signature = "Server signature invalid (check door key)",
}

function proto.fingerprint(cardId)
  return sha2.hex("fp:" .. cardId):sub(1, 24)
end

local function reqText(door, ts, nonce, fp, cardId)
  return table.concat({ "req", door, tostring(ts), nonce, fp, cardId }, "|")
end

function proto.makeRequest(doorId, doorSecret, cardId)
  local ts = math.floor(os.epoch("utc") / 1000)
  local nonce = sha2.tohex(sha2.random(12)) -- 24 hex chars
  local fp = proto.fingerprint(cardId)
  return {
    p = proto.VERSION, t = "req",
    door = doorId, ts = ts, nonce = nonce, fp = fp,
    mac = sha2.hmac(doorSecret, reqText(doorId, ts, nonce, fp, cardId)),
  }
end

--- Structural validation of an incoming request (does not check the MAC).
function proto.validRequest(req)
  return type(req) == "table" and req.p == proto.VERSION and req.t == "req"
    and type(req.door) == "string" and #req.door >= 1 and #req.door <= 32
    and type(req.nonce) == "string" and #req.nonce == 24
    and type(req.fp) == "string" and #req.fp == 24
    and type(req.mac) == "string" and #req.mac == 64
    and type(req.ts) == "number"
end

--- Checks the request MAC against a known card ID.
function proto.checkProof(req, doorSecret, cardId)
  local expected = sha2.hmac(doorSecret, reqText(req.door, req.ts, req.nonce, req.fp, cardId))
  return sha2.equals(req.mac, expected)
end

local function resMac(secret, r)
  return sha2.hmac(secret, table.concat({
    "res", r.door, r.nonce, r.ok and "1" or "0", r.reason, r.name,
    tostring(r.uses), tostring(r.exp),
  }, "|"))
end

--- result = { ok=bool, reason=string?, name=string?, uses=number?, exp=number? }
function proto.makeResponse(doorSecret, doorId, nonce, result)
  local r = {
    p = proto.VERSION, t = "res",
    door = doorId, nonce = nonce,
    ok = result.ok and true or false,
    reason = result.reason or "",
    name = result.name or "",
    uses = result.uses or -1,
    exp = result.exp or 0,
  }
  r.mac = resMac(doorSecret, r)
  return r
end

--- Returns true, or false + one of "malformed" | "nonce" | "mac".
function proto.checkResponse(res, doorId, doorSecret, nonce)
  if type(res) ~= "table" or res.p ~= proto.VERSION or res.t ~= "res" then
    return false, "malformed"
  end
  if res.nonce ~= nonce or res.door ~= doorId then return false, "nonce" end
  if type(res.mac) ~= "string" or type(res.reason) ~= "string" or type(res.name) ~= "string"
      or type(res.uses) ~= "number" or type(res.exp) ~= "number" or type(res.ok) ~= "boolean" then
    return false, "malformed"
  end
  if not sha2.equals(res.mac, resMac(doorSecret, res)) then return false, "mac" end
  return true
end

return proto

end

__mods["lib.cards"] = function()
-- lib/cards.lua
-- Card reader abstraction. Backends:
--   "disk" : floppy disks in a disk drive (file "lockcard" on the disk)
--   "nfc"  : NeoPeripherals NFC Reader / NFC Master  (see WARNING below)
--
-- Uniform interface (all backends and the composite returned by cards.open):
--   reader:start()                 begin polling (NFC)
--   reader:poll(ev)  -> id|false|nil, handle, backend
--        id    = card ID string           false = card present but unreadable
--        nil   = this event is not a card swipe
--   reader:release(backend, handle) eject / no-op
--   reader:readId()  -> id|nil     read whatever card is in the reader now
--   reader:write(id, label) -> ok, err
--   reader:erase()   -> ok, err

local sha2 = __require("lib.sha2")

local cards = {}

local MAGIC = "CCL2:"
local CARD_FILE = "lockcard"

function cards.newId() return sha2.tohex(sha2.random(16)) end -- 32 hex chars

local function encode(id) return MAGIC .. id end

local function strip(s)
  local n = #s
  while n > 0 do
    local b = s:byte(n)
    if b == 0 or b == 32 or b == 10 or b == 13 then n = n - 1 else break end
  end
  return s:sub(1, n)
end

local function decode(s)
  if type(s) ~= "string" then return nil end
  local id = strip(s):match("^" .. MAGIC .. "(%x+)$")
  if id and #id == 32 then return id end
  return nil
end

------------------------------------------------------------------------
-- Disk backend
------------------------------------------------------------------------
local Disk = {}
Disk.__index = Disk

function Disk.new()
  local drives = {}
  for _, name in ipairs(peripheral.getNames()) do
    if peripheral.getType(name) == "drive" then drives[#drives + 1] = name end
  end
  if #drives == 0 then return nil, "no disk drive attached" end
  local owned = {}
  for _, n in ipairs(drives) do owned[n] = true end
  return setmetatable({ kind = "disk", drives = drives, owned = owned, pending = {} }, Disk)
end

function Disk:start() end

function Disk:readSide(side)
  if not disk.isPresent(side) or not disk.hasData(side) then return nil end
  local mount = disk.getMountPath(side)
  if not mount then return nil end
  local path = fs.combine(mount, CARD_FILE)
  if not fs.exists(path) or fs.isDir(path) then return nil end
  local h = fs.open(path, "r")
  if not h then return nil end
  local data = h.readAll()
  h.close()
  return decode(data)
end

function Disk:poll(ev)
  if ev[1] == "disk" and self.owned[ev[2]] then
    -- give the mount a moment to settle, as the original script did
    self.pending[os.startTimer(0.25)] = ev[2]
  elseif ev[1] == "timer" and self.pending[ev[2]] then
    local side = self.pending[ev[2]]
    self.pending[ev[2]] = nil
    local id = self:readSide(side)
    if id then return id, side end
    return false, side
  end
  return nil
end

function Disk:release(side)
  if side then pcall(disk.eject, side) end
end

function Disk:findCard()
  for _, side in ipairs(self.drives) do
    if disk.isPresent(side) then return side end
  end
end

function Disk:readId()
  local side = self:findCard()
  if not side then return nil end
  return self:readSide(side)
end

function Disk:write(id, label)
  local side = self:findCard()
  if not side then return false, "no card inserted" end
  if not disk.hasData(side) then return false, "not a data disk (use a floppy)" end
  local mount = disk.getMountPath(side)
  local h = mount and fs.open(fs.combine(mount, CARD_FILE), "w")
  if not h then return false, "cannot write to disk" end
  h.write(encode(id))
  h.close()
  if label then pcall(disk.setLabel, side, label) end
  return true
end

function Disk:erase()
  local side = self:findCard()
  if not side then return false, "no card inserted" end
  local mount = disk.getMountPath(side)
  if mount then pcall(fs.delete, fs.combine(mount, CARD_FILE)) end
  pcall(disk.setLabel, side, nil)
  return true
end

------------------------------------------------------------------------
-- Classic Peripherals NFC Reader (event-driven)
--
-- Peripheral type: nfc_reader
-- Read event:  nfc_data(event, side, cardDataString, cardPublicKeyString)
-- Write event: nfc_write(event, side, successBoolean, reasonString)
-- API: write(data, label, readonly, privateKey), cancelWrite()
--
-- Card payload remains CCL2:<32 hex chars>, so NFC and floppy cards share
-- the same server-side authorization format. Public-key authentication is
-- deliberately not required; the server remains the authority.
------------------------------------------------------------------------
cards.NFC_CFG = {
  peripheralType = "nfc_reader",
  writeTimeout = 12,
}

local Nfc = {}
Nfc.__index = Nfc

function Nfc.new()
  local names = {}
  for _, name in ipairs(peripheral.getNames()) do
    if peripheral.getType(name) == cards.NFC_CFG.peripheralType then
      names[#names + 1] = name
    end
  end
  if #names == 0 then return nil, "no Classic Peripherals nfc_reader attached" end
  local owned = {}
  for _, name in ipairs(names) do owned[name] = true end
  return setmetatable({ kind = "nfc", names = names, owned = owned, lastRead = {} }, Nfc)
end

function Nfc:start() end

function Nfc:poll(ev)
  if ev[1] == "nfc_data" and self.owned[ev[2]] then
    local name, payload = ev[2], ev[3]
    local id = decode(payload)
    self.lastRead[name] = id or false
    if id then return id, name end
    return false, name
  end
  return nil
end

function Nfc:release() end

-- NFC reads arrive as events, not synchronous peripheral methods. This cache
-- is only for diagnostics; callers that need a fresh tap must wait for poll().
function Nfc:readId()
  for _, name in ipairs(self.names) do
    local id = self.lastRead[name]
    if type(id) == "string" then return id end
  end
  return nil
end

function Nfc:write(id, label)
  local payload = encode(id)
  local lastErr = "no NFC reader accepted the write"
  for _, name in ipairs(self.names) do
    local called, err = pcall(peripheral.call, name, "write", payload, label or "CCL2 Access Card", false, nil)
    if called then
      local timer = os.startTimer(cards.NFC_CFG.writeTimeout)
      while true do
        local ev, side, success, reason = os.pullEventRaw()
        if ev == "nfc_write" and side == name then
          if success then return true end
          return false, (type(reason) == "string" and reason ~= "" and reason) or "NFC write failed"
        elseif ev == "timer" and side == timer then
          pcall(peripheral.call, name, "cancelWrite")
          return false, "NFC write timed out; keep the card on the reader and retry"
        elseif ev == "peripheral_detach" and side == name then
          return false, "NFC reader detached during write"
        end
      end
    end
    lastErr = tostring(err)
  end
  return false, lastErr
end

function Nfc:erase()
  local lastErr = "no NFC reader accepted the erase"
  for _, name in ipairs(self.names) do
    local called, err = pcall(peripheral.call, name, "write", "", "Erased access card", false, nil)
    if called then
      local timer = os.startTimer(cards.NFC_CFG.writeTimeout)
      while true do
        local ev, side, success, reason = os.pullEventRaw()
        if ev == "nfc_write" and side == name then
          if success then return true end
          return false, (type(reason) == "string" and reason ~= "" and reason) or "NFC erase failed"
        elseif ev == "timer" and side == timer then
          pcall(peripheral.call, name, "cancelWrite")
          return false, "NFC erase timed out"
        elseif ev == "peripheral_detach" and side == name then
          return false, "NFC reader detached during erase"
        end
      end
    end
    lastErr = tostring(err)
  end
  return false, lastErr
end

------------------------------------------------------------------------
-- Composite
------------------------------------------------------------------------
local Composite = {}
Composite.__index = Composite

--- cards.open({"disk", "nfc"}) -> reader | nil, errorText
function cards.open(kinds)
  local ctors = { disk = Disk.new, nfc = Nfc.new }
  local readers, errors = {}, {}
  for _, k in ipairs(kinds) do
    local ctor = ctors[k]
    if ctor then
      local r, err = ctor()
      if r then readers[#readers + 1] = r else errors[#errors + 1] = k .. ": " .. err end
    end
  end
  if #readers == 0 then return nil, table.concat(errors, "; ") end
  return setmetatable({ readers = readers }, Composite)
end

function Composite:describe()
  local k = {}
  for _, r in ipairs(self.readers) do k[#k + 1] = r.kind end
  return table.concat(k, "+")
end

function Composite:start()
  for _, r in ipairs(self.readers) do r:start() end
end

function Composite:poll(ev)
  for _, r in ipairs(self.readers) do
    local id, handle = r:poll(ev)
    if id ~= nil then return id, handle, r end
  end
  return nil
end

function Composite:release(backend, handle)
  if backend then backend:release(handle) end
end

function Composite:readId()
  for _, r in ipairs(self.readers) do
    local id = r:readId()
    if id then return id end
  end
end

function Composite:write(id, label)
  local lastErr = "no reader"
  for _, r in ipairs(self.readers) do
    local ok, err = r:write(id, label)
    if ok then return true end
    lastErr = err
  end
  return false, lastErr
end

function Composite:erase()
  local lastErr = "no reader"
  for _, r in ipairs(self.readers) do
    local ok, err = r:erase()
    if ok then return true end
    lastErr = err
  end
  return false, lastErr
end

return cards

end

__mods["lib.ui"] = function()
-- lib/ui.lua
-- Small drawing helpers that work on any term-like object (the computer
-- screen or a monitor). On non-colour screens, coloured areas are rendered
-- inverted (black on white) so highlights stay visible.

local ui = {}

local function isColor(t) return t.isColor and t.isColor() end

function ui.style(t, fg, bg)
  fg = fg or colors.white
  bg = bg or colors.black
  if not isColor(t) then
    if bg ~= colors.black then fg, bg = colors.black, colors.white
    else fg, bg = colors.white, colors.black end
  end
  t.setTextColor(fg)
  t.setBackgroundColor(bg)
end

function ui.clear(t, bg)
  ui.style(t, colors.white, bg or colors.black)
  t.clear()
  t.setCursorPos(1, 1)
end

function ui.fill(t, x, y, w, h, bg)
  if w <= 0 or h <= 0 then return end
  ui.style(t, colors.white, bg)
  local row = string.rep(" ", w)
  for yy = y, y + h - 1 do
    t.setCursorPos(x, yy)
    t.write(row)
  end
end

function ui.text(t, x, y, s, fg, bg)
  local w = t.getSize()
  if x > w or y < 1 then return end
  if x < 1 then s = s:sub(2 - x); x = 1 end
  s = s:sub(1, w - x + 1)
  ui.style(t, fg, bg)
  t.setCursorPos(x, y)
  t.write(s)
end

function ui.center(t, y, s, fg, bg)
  local w = t.getSize()
  ui.text(t, math.floor((w - #s) / 2) + 1, y, s, fg, bg)
end

--- Progress bar. frac is 0..1.
function ui.bar(t, x, y, w, frac, fg, bg)
  frac = math.max(0, math.min(1, frac))
  local n = math.floor(w * frac + 0.5)
  t.setCursorPos(x, y)
  if isColor(t) then
    ui.style(t, colors.white, fg)
    t.write(string.rep(" ", n))
    ui.style(t, colors.white, bg)
    t.write(string.rep(" ", w - n))
  else
    ui.style(t, colors.white, colors.black)
    t.write(string.rep("#", n) .. string.rep("-", w - n))
  end
end

function ui.frame(t, x, y, w, h, title, fg, bg)
  if w < 4 or h < 2 then return end
  ui.style(t, fg, bg)
  t.setCursorPos(x, y);         t.write("+" .. string.rep("-", w - 2) .. "+")
  for yy = y + 1, y + h - 2 do
    t.setCursorPos(x, yy);      t.write("|" .. string.rep(" ", w - 2) .. "|")
  end
  t.setCursorPos(x, y + h - 1); t.write("+" .. string.rep("-", w - 2) .. "+")
  if title then t.setCursorPos(x + 2, y); t.write(" " .. title .. " ") end
end

local SPIN = { "|", "/", "-", "\\" }
function ui.spinner(i) return SPIN[(i % #SPIN) + 1] end

function ui.wrap(s, width)
  local lines, line = {}, ""
  for word in s:gmatch("%S+") do
    if #line + #word + 1 > width and #line > 0 then
      lines[#lines + 1] = line
      line = word
    else
      line = (#line > 0) and (line .. " " .. word) or word
    end
  end
  if #line > 0 then lines[#lines + 1] = line end
  return lines
end

--- 93784 -> "1d 2h", 125 -> "2m 5s"
function ui.duration(sec)
  sec = math.max(0, math.floor(sec))
  local d = math.floor(sec / 86400); sec = sec % 86400
  local h = math.floor(sec / 3600);  sec = sec % 3600
  local m = math.floor(sec / 60);    sec = sec % 60
  if d > 0 then return d .. "d " .. h .. "h" end
  if h > 0 then return h .. "h " .. m .. "m" end
  if m > 0 then return m .. "m " .. sec .. "s" end
  return sec .. "s"
end

--- "30m" / "12h" / "7d" / "90" (seconds) -> seconds, or nil if invalid.
function ui.parseDuration(s)
  local n, unit = s:match("^%s*(%d+)%s*([smhdSMHD]?)%s*$")
  if not n then return nil end
  n = tonumber(n)
  local mult = ({ s = 1, m = 60, h = 3600, d = 86400 })[unit:lower()] or 1
  if n <= 0 then return nil end
  return n * mult
end

--- Finds a monitor. spec: nil = auto, false = none, string = peripheral name.
function ui.findMonitor(spec, scale)
  if spec == false then return nil end
  local m
  if type(spec) == "string" then m = peripheral.wrap(spec) else m = peripheral.find("monitor") end
  if m and m.setTextScale then
    m.setTextScale(scale or 1)
    m.setCursorBlink(false)
    return m
  end
  return nil
end

return ui

end

local function runServer()
local CONFIG = SERVER_CONFIG
-- server.lua  (save as startup.lua on the server computer)
-- Needs: modem. Optional: monitor (live dashboard), disk drive / NFC master
-- (to enroll and wipe cards), keyboard (admin console).


if CONFIG.adminPassword == "" then
  error("Set CONFIG.adminPassword in server.lua before running.", 0)
end

os.pullEvent = os.pullEventRaw
settings.set("shell.allow_disk_startup", false)

local sha2  = __require("lib.sha2")
local proto = __require("lib.proto")
local cards = __require("lib.cards")
local ui    = __require("lib.ui")

local function nowMs() return os.epoch("utc") end
local function dirty() os.queueEvent("lock_dirty") end

local state = {
  db = { version = 2, cards = {}, doors = {} },
  byFp = {},
  log = {},
  granted = 0,
  denied = 0,
  nonces = {},
  flash = nil,
  doorSeen = {},
}
local reader -- card reader (may be nil)

------------------------------------------------------------------------
-- Database (atomic writes, data-only parsing)
------------------------------------------------------------------------
local function readFile(path)
  local h = fs.open(path, "r")
  if not h then return nil end
  local s = h.readAll()
  h.close()
  return s
end

local function reindex()
  state.byFp = {}
  for _, c in ipairs(state.db.cards) do state.byFp[c.fp] = c end
end

local function loadDb()
  local src
  if fs.exists(CONFIG.dbFile) then src = CONFIG.dbFile
  elseif fs.exists(CONFIG.dbFile .. ".tmp") then src = CONFIG.dbFile .. ".tmp" end
  if src then
    local data = textutils.unserialize(readFile(src) or "")
    if type(data) ~= "table" or type(data.cards) ~= "table" then
      error("Could not parse " .. src .. " - repair or remove it (refusing to overwrite).", 0)
    end
    if type(data.doors) ~= "table" then data.doors = {} end
    state.db = data
  end
  reindex()
end

local function saveDb()
  local tmp = CONFIG.dbFile .. ".tmp"
  local bak = CONFIG.dbFile .. ".bak"
  local h = fs.open(tmp, "w")
  if not h then error("cannot open " .. tmp .. " for writing", 0) end
  local ok, err = pcall(function()
    h.write(textutils.serialize(state.db))
    h.close()
  end)
  if not ok then
    pcall(h.close)
    error("could not write database temporary file: " .. tostring(err), 0)
  end

  -- Preserve the last known-good database until the new file is in place.
  if fs.exists(bak) then fs.delete(bak) end
  local hadOld = fs.exists(CONFIG.dbFile)
  if hadOld then fs.move(CONFIG.dbFile, bak) end
  local moved, moveErr = pcall(fs.move, tmp, CONFIG.dbFile)
  if not moved then
    if hadOld and fs.exists(bak) and not fs.exists(CONFIG.dbFile) then
      pcall(fs.move, bak, CONFIG.dbFile)
    end
    error("could not replace database: " .. tostring(moveErr), 0)
  end
  if fs.exists(bak) then pcall(fs.delete, bak) end
end

local function sortedDoorIds()
  local ids = {}
  for id in pairs(state.db.doors) do ids[#ids + 1] = id end
  table.sort(ids)
  return ids
end

------------------------------------------------------------------------
-- Logging
------------------------------------------------------------------------
local function describe(e)
  if e.kind == "access" then
    return (e.ok and "GRANT " or "DENY  ") .. (e.door or "?") .. " " .. (e.who or "?")
      .. (e.reason and (" (" .. e.reason .. ")") or "")
  end
  return "ADMIN " .. (e.text or "")
end

local function addLog(entry)
  entry.t = nowMs()
  state.log[#state.log + 1] = entry
  while #state.log > CONFIG.maxLog do table.remove(state.log, 1) end
  if entry.kind == "access" then
    if entry.ok then state.granted = state.granted + 1 else state.denied = state.denied + 1 end
  end

  if fs.exists(CONFIG.logFile) and fs.getSize(CONFIG.logFile) > 65536 then
    local old = CONFIG.logFile .. ".old"
    if fs.exists(old) then fs.delete(old) end
    fs.move(CONFIG.logFile, old)
  end
  local h = fs.open(CONFIG.logFile, "a")
  if h then
    h.writeLine(os.date("%Y-%m-%d %H:%M:%S", math.floor(entry.t / 1000)) .. " | " .. describe(entry))
    h.close()
  end
  dirty()
end

local function flash(title, sub, color)
  state.flash = { title = title, sub = sub or "", color = color, untilMs = nowMs() + 4000 }
  dirty()
end

------------------------------------------------------------------------
-- Request handling
------------------------------------------------------------------------
local function transmit(side, replyCh, res)
  pcall(peripheral.call, side, "transmit", replyCh, CONFIG.channel, res)
end

local function pruneNonces()
  local cutoff = nowMs() - CONFIG.nonceTTL * 1000
  for k, v in pairs(state.nonces) do
    if v.at < cutoff then state.nonces[k] = nil end
  end
end

local function handleRequest(side, replyCh, req)
  if type(replyCh) ~= "number" or not proto.validRequest(req) then return end

  local door = state.db.doors[req.door]
  if not door then
    addLog { kind = "access", ok = false, door = req.door, who = "?", reason = "unknown door" }
    return
  end
  state.doorSeen[req.door] = nowMs()

  pruneNonces()
  local key = req.door .. req.nonce
  local cached = state.nonces[key]
  if cached then -- retransmission: answer identically, never consume a second use
    transmit(side, replyCh, cached.res)
    return
  end

  local function finish(result, who)
    local res = proto.makeResponse(door.secret, req.door, req.nonce, result)
    state.nonces[key] = { at = nowMs(), res = res }
    transmit(side, replyCh, res)
    addLog {
      kind = "access", ok = result.ok, door = req.door,
      who = who or result.name or "?", reason = (not result.ok) and result.reason or nil,
    }
  end

  local now = nowMs()
  if math.abs(math.floor(now / 1000) - req.ts) > proto.MAX_SKEW then
    return finish({ ok = false, reason = "stale" })
  end

  local card = state.byFp[req.fp]
  if not card then return finish({ ok = false, reason = "unknown_card" }) end

  if not proto.checkProof(req, door.secret, card.id) then
    return finish({ ok = false, reason = "bad_proof", name = "" }, card.name .. " (bad proof)")
  end

  local reason
  if card.disabled then reason = "disabled"
  elseif (card.expires or 0) ~= 0 and card.expires <= now then reason = "expired"
  elseif card.uses ~= -1 and card.uses <= 0 then reason = "no_uses"
  elseif card.doors and not card.doors[req.door] then reason = "wrong_door" end
  if reason then
    return finish({ ok = false, reason = reason, name = card.name }, card.name)
  end

  local decremented = false
  local previousLastUsed = card.lastUsed
  local previousUseCount = card.useCount or 0
  if card.uses > 0 then card.uses = card.uses - 1; decremented = true end
  card.lastUsed = now
  card.useCount = previousUseCount + 1

  local saved = pcall(saveDb)
  if not saved then
    if decremented then card.uses = card.uses + 1 end
    card.useCount = previousUseCount
    card.lastUsed = previousLastUsed
    return finish({ ok = false, reason = "server_error", name = card.name }, card.name)
  end

  finish({ ok = true, name = card.name, uses = card.uses, exp = card.expires or 0 }, card.name)
end

local function netLoop()
  while true do
    local _, side, ch, rch, msg = os.pullEventRaw("modem_message")
    if ch == CONFIG.channel then
      local ok, err = pcall(handleRequest, side, rch, msg)
      if not ok then addLog { kind = "admin", text = "handler error: " .. tostring(err) } end
    end
  end
end

------------------------------------------------------------------------
-- Dashboard (monitor)
------------------------------------------------------------------------
local function drawDash(t)
  local w, h = t.getSize()
  local now = nowMs()
  ui.clear(t, colors.black)

  ui.fill(t, 1, 1, w, 3, colors.blue)
  ui.center(t, 2, "ACCESS CONTROL", colors.white, colors.blue)
  ui.text(t, math.max(1, w - 8), 2, os.date("%H:%M:%S"), colors.lightBlue, colors.blue)

  local doorCount = 0
  for _ in pairs(state.db.doors) do doorCount = doorCount + 1 end
  ui.text(t, 2, 4, "Cards " .. #state.db.cards .. "  Doors " .. doorCount, colors.white)
  local stats = "Granted " .. state.granted .. "  Denied " .. state.denied
  ui.text(t, math.max(1, w - #stats), 4, stats, colors.lightGray)
  ui.text(t, 1, 5, string.rep("-", w), colors.gray)

  local rows = h - 5
  for i = 0, rows - 1 do
    local e = state.log[#state.log - i]
    if not e then break end
    local y = 6 + i
    ui.text(t, 2, y, os.date("%H:%M:%S", math.floor(e.t / 1000)), colors.lightGray)
    if e.kind == "access" then
      ui.text(t, 11, y, e.ok and "OK" or "NO", e.ok and colors.lime or colors.red)
      local rest = (e.door or "?") .. "  " .. (e.who or "?")
      if e.reason then rest = rest .. "  [" .. e.reason .. "]" end
      ui.text(t, 14, y, rest, colors.white)
    else
      ui.text(t, 11, y, "--", colors.yellow)
      ui.text(t, 14, y, e.text or "", colors.lightGray)
    end
  end

  local f = state.flash
  if f and now < f.untilMs then
    local bh = 5
    local y0 = math.max(1, math.floor((h - bh) / 2))
    ui.fill(t, 3, y0, math.max(1, w - 4), bh, f.color)
    ui.center(t, y0 + 1, f.title, colors.white, f.color)
    ui.center(t, y0 + 3, f.sub, colors.white, f.color)
  end
end

local function dashLoop()
  local mon = ui.findMonitor(CONFIG.monitor, CONFIG.monitorScale)
  if not mon and CONFIG.monitor == false then
    while true do os.pullEventRaw() end
  end
  local timer = os.startTimer(1)
  while true do
    if not mon then mon = ui.findMonitor(CONFIG.monitor, CONFIG.monitorScale) end
    if mon then
      local ok = pcall(drawDash, mon)
      if not ok then mon = nil end
    end
    local ev, p
    repeat
      ev, p = os.pullEventRaw()
    until (ev == "timer" and p == timer) or ev == "lock_dirty"
      or ev == "monitor_resize" or ev == "peripheral"
    if ev == "timer" and p == timer then timer = os.startTimer(1) end
  end
end

------------------------------------------------------------------------
-- Admin console (computer terminal)
------------------------------------------------------------------------
local function header(title)
  local t = term.current()
  local w = t.getSize()
  ui.clear(t, colors.black)
  ui.fill(t, 1, 1, w, 1, colors.blue)
  ui.text(t, 2, 1, "ACCESS CONTROL  |  " .. title, colors.white, colors.blue)
  ui.style(t, colors.white, colors.black)
  t.setCursorPos(1, 3)
end

local function pause()
  print("")
  print("Press any key...")
  os.pullEventRaw("key")
end

local function confirm(msg)
  print(msg .. " (y/n)")
  while true do
    local _, ch = os.pullEventRaw("char")
    if ch == "y" or ch == "Y" then return true end
    if ch == "n" or ch == "N" then return false end
  end
end

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

local function cardStatus(c, now)
  if c.disabled then return "suspended", colors.gray end
  if (c.expires or 0) ~= 0 and c.expires <= now then return "expired", colors.red end
  if c.uses ~= -1 and c.uses <= 0 then return "used up", colors.orange end
  return "active", colors.lime
end

--- Pages through the cards. If `selecting`, returns the chosen index or nil.
local function showCardList(selecting)
  local t = term.current()
  local list = state.db.cards
  if #list == 0 then
    header("Cards")
    print("No cards enrolled yet.")
    pause()
    return nil
  end
  local _, h = t.getSize()
  local per = math.max(3, h - 6)
  local first = 1

  while true do
    header(selecting and "Select a card" or "Cards")
    local now = nowMs()
    ui.text(t, 1, 3, string.format("%-3s %-14s %-8s %-5s %s", "#", "Name", "Status", "Uses", "Expires"), colors.lightGray)
    for row = 0, per - 1 do
      local i = first + row
      local c = list[i]
      if not c then break end
      local status, col = cardStatus(c, now)
      local exp = ((c.expires or 0) == 0) and "never" or ui.duration((c.expires - now) / 1000)
      if status == "expired" then exp = "-" end
      local uses = (c.uses == -1) and "inf" or tostring(c.uses)
      ui.text(t, 1, 4 + row, string.format("%-3d %-14s", i, c.name:sub(1, 14)), colors.white)
      ui.text(t, 20, 4 + row, string.format("%-8s", status), col)
      ui.text(t, 29, 4 + row, string.format("%-5s %s", uses, exp), colors.white)
    end

    local last = first + per - 1 >= #list
    if last and selecting then
      ui.style(t, colors.white, colors.black)
      t.setCursorPos(1, h)
      t.clearLine()
      write("Card # (blank = cancel): ")
      local n = tonumber(read())
      if n and list[n] then return n end
      return nil
    end

    ui.text(t, 1, h, last and "[Q] back" or "[Space] next page   [Q] back", colors.gray)
    local ch
    repeat
      local _, c = os.pullEventRaw("char")
      ch = c
    until ch == "q" or ch == "Q" or (ch == " " and not last)
    if ch == " " then first = first + per else return nil end
  end
end

local function enroll()
  header("Enroll new card")
  if not reader then print("No card reader attached."); pause(); return end

  local doorIds = sortedDoorIds()
  if #doorIds == 0 then
    print("No doors exist yet. Add one first (Doors menu).")
    pause()
    return
  end

  write("Card holder name: ")
  local name = trim(read())
  if name == "" or #name > 32 then print("Name must be 1-32 characters."); pause(); return end

  write("Valid for (30m, 12h, 7d; blank = forever): ")
  local durText = trim(read())
  local expires = 0
  if durText ~= "" then
    local secs = ui.parseDuration(durText)
    if not secs then print("Invalid duration."); pause(); return end
    expires = nowMs() + secs * 1000
  end

  write("Max uses (blank = unlimited): ")
  local usesText = trim(read())
  local uses = -1
  if usesText ~= "" then
    uses = tonumber(usesText)
    if not uses or uses < 1 or uses ~= math.floor(uses) then print("Invalid number."); pause(); return end
  end

  print("Doors: " .. table.concat(doorIds, ", "))
  write("Allowed doors (comma-separated; blank = all): ")
  local doorText = trim(read())
  local doors
  if doorText ~= "" then
    doors = {}
    for d in doorText:gmatch("[^,%s]+") do
      if not state.db.doors[d] then print("Unknown door: " .. d); pause(); return end
      doors[d] = true
    end
  end

  print("")
  print("Present/insert a card at the reader.  [Q] cancels.")
  local id, handle, backend
  while handle == nil do
    local ev = { os.pullEventRaw() }
    if ev[1] == "char" and (ev[2] == "q" or ev[2] == "Q") then
      print("Cancelled."); pause(); return
    end
    local got, h, b = reader:poll(ev)
    if got ~= nil and h ~= nil then
      -- false means a blank or unreadable card was presented. It can still be
      -- enrolled; only a valid existing CCL2 ID participates in overwrite checks.
      id, handle, backend = got, h, b
    end
  end

  if type(id) == "string" then
    local owner = state.byFp[proto.fingerprint(id)]
    if owner then
      print("This card is already enrolled as '" .. owner.name .. "'.")
      if not confirm("Overwrite it? (the old entry will be deleted)") then return end
      for i, c in ipairs(state.db.cards) do
        if c == owner then table.remove(state.db.cards, i) break end
      end
      reindex()
    end
  end

  local newId = cards.newId()
  local written, writeErr = reader:write(newId, name)
  if not written then
    print("Card write failed: " .. tostring(writeErr))
    pause()
    return
  end

  local card = {
    id = newId, fp = proto.fingerprint(newId), name = name,
    created = nowMs(), expires = expires, uses = uses, doors = doors,
    useCount = 0, lastUsed = 0,
  }
  state.db.cards[#state.db.cards + 1] = card
  reindex()
  local saved, err = pcall(saveDb)

  addLog { kind = "admin", text = "enrolled card '" .. name .. "'" }
  flash("CARD ENROLLED", name, colors.green)
  print(saved and ("Card '" .. name .. "' enrolled.") or ("WARNING: card written but DB save failed: " .. tostring(err)))
  pause()
end

local function toggleSuspend()
  local n = showCardList(true)
  if not n then return end
  local c = state.db.cards[n]
  c.disabled = not c.disabled or nil
  pcall(saveDb)
  addLog { kind = "admin", text = (c.disabled and "suspended '" or "resumed '") .. c.name .. "'" }
  flash(c.disabled and "CARD SUSPENDED" or "CARD RESUMED", c.name, c.disabled and colors.orange or colors.green)
end

local function revokeCard()
  local n = showCardList(true)
  if not n then return end
  local c = state.db.cards[n]
  header("Revoke card")
  if not confirm("Delete '" .. c.name .. "' permanently?") then return end
  table.remove(state.db.cards, n)
  reindex()
  local saved, err = pcall(saveDb)
  addLog { kind = "admin", text = "revoked '" .. c.name .. "'" }
  flash("CARD REVOKED", c.name, colors.red)
  print(saved and "Revoked. The physical card no longer works." or ("Save failed: " .. tostring(err)))
  pause()
end

local function wipeCard()
  header("Wipe card in reader")
  if not reader then print("No card reader attached."); pause(); return end
  print("Present/insert the card to erase. [Q] cancels.")
  local id = reader:readId()
  while id == nil do
    local ev = { os.pullEventRaw() }
    if ev[1] == "char" and (ev[2] == "q" or ev[2] == "Q") then
      print("Cancelled."); pause(); return
    end
    local got = reader:poll(ev)
    if got ~= nil then id = got end
  end
  local owner = type(id) == "string" and state.byFp[proto.fingerprint(id)] or nil
  print(owner and ("Card belongs to '" .. owner.name .. "'.") or "Card is not in the database or is unreadable.")
  if not confirm("Erase this physical card and remove any matching database entry?") then return end
  if owner then
    for i, c in ipairs(state.db.cards) do
      if c == owner then table.remove(state.db.cards, i) break end
    end
    reindex()
    pcall(saveDb)
  end
  local ok, err = reader:erase()
  addLog { kind = "admin", text = "wiped card" .. (owner and (" '" .. owner.name .. "'") or "") }
  print(ok and "Card erased." or ("Could not erase card: " .. tostring(err)))
  pause()
end

local function doorsMenu()
  while true do
    header("Doors")
    local ids = sortedDoorIds()
    if #ids == 0 then print("(no doors yet)") end
    for _, id in ipairs(ids) do
      local d = state.db.doors[id]
      local seen = state.doorSeen[id] and (ui.duration((nowMs() - state.doorSeen[id]) / 1000) .. " ago") or "never seen"
      print(string.format("%-14s %-16s %s", id, (d.name or ""):sub(1, 16), seen))
    end
    print("")
    print("1) Add door   2) Show door key   3) Remove door   4) Export pairing file   Q) Back")
    local _, ch = os.pullEventRaw("char")

    if ch == "q" or ch == "Q" then return
    elseif ch == "1" then
      header("Add door")
      write("Door ID (letters, digits, - _): ")
      local id = trim(read())
      if not id:match("^[%w_%-]+$") or #id > 32 then print("Invalid ID."); pause()
      elseif state.db.doors[id] then print("That door already exists."); pause()
      else
        write("Display name: ")
        local name = trim(read())
        local secret = sha2.tohex(sha2.random(16))
        state.db.doors[id] = { name = name ~= "" and name or id, secret = secret }
        local saved = pcall(saveDb)
        addLog { kind = "admin", text = "added door '" .. id .. "'" }
        print("")
        print("Put these in the door's client.lua:")
        print('  doorId = "' .. id .. '"')
        print('  secret = "' .. secret .. '"')
        if not saved then print("WARNING: database save failed!") end
        pause()
      end
    elseif ch == "2" then
      header("Door key")
      write("Door ID: ")
      local d = state.db.doors[trim(read())]
      if d then print("Key: " .. d.secret) else print("Unknown door.") end
      pause()
    elseif ch == "3" then
      header("Remove door")
      write("Door ID: ")
      local id = trim(read())
      if state.db.doors[id] and confirm("Remove door '" .. id .. "'?") then
        state.db.doors[id] = nil
        for _, c in ipairs(state.db.cards) do
          if c.doors then c.doors[id] = nil end
        end
        pcall(saveDb)
        addLog { kind = "admin", text = "removed door '" .. id .. "'" }
      end

    elseif ch == "4" then
      header("Export door pairing")
      write("Door ID: ")
      local id = trim(read())
      local door = state.db.doors[id]
      if not door then
        print("Unknown door.")
        pause()
      else
        local target
        for _, side in ipairs(peripheral.getNames()) do
          if peripheral.getType(side) == "drive" and disk.isPresent(side) and disk.hasData(side) then
            target = side
            break
          end
        end
        local mount = target and disk.getMountPath(target)
        if not mount then
          print("Insert a writable floppy into a disk drive.")
          pause()
        else
          print("WARNING: the pairing file contains the door secret in plain text.")
          print("Keep the floppy secure and remove the file after installing the client.")
          if confirm("Export pairing file for '" .. id .. "'?") then
            local path = fs.combine(mount, "doorpair.txt")
            local h = fs.open(path, "w")
            if not h then
              print("Could not write pairing file.")
            else
              h.writeLine(id)
              h.writeLine(door.secret)
              h.close()
              pcall(disk.setLabel, target, "DOOR-PAIR")
              print("Exported to doorpair.txt. Remove it after client setup.")
            end
            pause()
          end
        end
      end
    end
  end
end

local function viewLog()
  local t = term.current()
  header("Access log")
  local w, h = t.getSize()
  for i = 0, h - 5 do
    local e = state.log[#state.log - i]
    if not e then break end
    local col = (e.kind ~= "access") and colors.yellow or (e.ok and colors.lime or colors.red)
    ui.text(t, 1, 3 + i, os.date("%H:%M:%S", math.floor(e.t / 1000)) .. " " .. describe(e), col)
  end
  ui.text(t, 1, h, "Press any key...", colors.gray)
  os.pullEventRaw("key")
end

local function purgeDead()
  header("Purge dead cards")
  local now = nowMs()
  local count = 0
  for _, c in ipairs(state.db.cards) do
    local s = cardStatus(c, now)
    if s == "expired" or s == "used up" then count = count + 1 end
  end
  if count == 0 then print("Nothing to purge."); pause(); return end
  if not confirm("Delete " .. count .. " expired / used-up card(s)?") then return end
  for i = #state.db.cards, 1, -1 do
    local s = cardStatus(state.db.cards[i], now)
    if s == "expired" or s == "used up" then table.remove(state.db.cards, i) end
  end
  reindex()
  pcall(saveDb)
  addLog { kind = "admin", text = "purged " .. count .. " dead card(s)" }
  print("Purged " .. count .. " card(s).")
  pause()
end

local function adminLoop()
  local unlockedUntil = 0
  local fails, lockoutUntil = 0, 0

  local function lockedScreen()
    header("Locked")
    print("Press any key to unlock.")
    os.pullEventRaw("key")
  end

  local function tryUnlock()
    if nowMs() < lockoutUntil then
      header("Locked")
      print("Too many attempts. Try again in " .. math.ceil((lockoutUntil - nowMs()) / 1000) .. "s.")
      sleep(2)
      return false
    end
    header("Unlock")
    write("Admin password: ")
    local pw = read("*")
    if pw == CONFIG.adminPassword then
      fails = 0
      unlockedUntil = nowMs() + CONFIG.unlockSeconds * 1000
      addLog { kind = "admin", text = "console unlocked" }
      return true
    end
    fails = fails + 1
    addLog { kind = "admin", text = "FAILED console login" }
    if fails >= 3 then lockoutUntil = nowMs() + 30000; fails = 0 end
    print("Wrong password.")
    sleep(1.5)
    return false
  end

  local actions = {
    ["1"] = enroll, ["2"] = function() showCardList(false) end, ["3"] = toggleSuspend,
    ["4"] = revokeCard, ["5"] = wipeCard, ["6"] = doorsMenu, ["7"] = viewLog, ["8"] = purgeDead,
  }

  while true do
    lockedScreen()
    if tryUnlock() then
      while nowMs() < unlockedUntil do
        header("Main menu")
        print("1) Enroll new card")
        print("2) List cards")
        print("3) Suspend / resume card")
        print("4) Revoke card")
        print("5) Wipe card in reader")
        print("6) Doors")
        print("7) Access log")
        print("8) Purge expired / used-up cards")
        print("L) Lock now")
        print("")
        print("Reader: " .. (reader and reader:describe() or "none"))
        local _, h = term.getSize()
        local countdownY = h

        local timer = os.startTimer(1)
        local action
        while nowMs() < unlockedUntil do
          local ev, p = os.pullEventRaw()
          if ev == "char" then
            if p == "l" or p == "L" then unlockedUntil = 0
            elseif actions[p] then action = actions[p] end
            break
          elseif ev == "timer" and p == timer then
            timer = os.startTimer(1)
            ui.text(term.current(), 1, countdownY,
              string.format("Auto-lock in %ds   ", math.max(0, math.ceil((unlockedUntil - nowMs()) / 1000))),
              colors.gray)
          end
        end
        if action then
          local ok, err = pcall(action)
          if not ok then
            header("Error")
            printError(tostring(err))
            pause()
          end
          unlockedUntil = nowMs() + CONFIG.unlockSeconds * 1000
        end
      end
    end
  end
end

------------------------------------------------------------------------
-- Boot
------------------------------------------------------------------------
local function main()
  sha2.selftest()
  loadDb()
  reader = cards.open(CONFIG.readers)

  local opened = 0
  for _, name in ipairs(peripheral.getNames()) do
    if peripheral.getType(name) == "modem" then
      peripheral.call(name, "open", CONFIG.channel)
      opened = opened + 1
    end
  end
  if opened == 0 then error("No modem attached.", 0) end

  addLog { kind = "admin", text = "server started (" .. #state.db.cards .. " cards)" }
  parallel.waitForAny(netLoop, adminLoop, dashLoop)
end

local ok, err = pcall(main)
if not ok then
  printError(err)
  print("")
  print("The server stopped safely. Press R to reboot, or Q to leave it stopped.")
  while true do
    local ev, ch = os.pullEventRaw()
    if ev == "char" and (ch == "r" or ch == "R") then os.reboot() end
    if ev == "char" and (ch == "q" or ch == "Q") then return end
  end
end

end

local function runClient()
local CONFIG = CLIENT_CONFIG
-- client.lua  (save as startup.lua on each door computer)
-- Needs: modem + (disk drive and/or NFC reader). Optional: monitor, speaker.
-- Create the door on the server first (Doors menu) and copy its ID + key here.


if CONFIG.doorId == "" or CONFIG.secret == "" then
  error("Set CONFIG.doorId and CONFIG.secret in client.lua (create the door on the server first).", 0)
end

os.pullEvent = os.pullEventRaw
settings.set("shell.allow_disk_startup", false)

local sha2  = __require("lib.sha2")
local proto = __require("lib.proto")
local cards = __require("lib.cards")
local ui    = __require("lib.ui")

local function nowMs() return os.epoch("utc") end

local function main()
  sha2.selftest()

  local modem = peripheral.find("modem")
  if not modem then error("No modem attached.", 0) end
  local reader, rerr = cards.open(CONFIG.readers)
  if not reader then error("No card reader: " .. tostring(rerr), 0) end
  local speaker = peripheral.find("speaker")
  local screen = ui.findMonitor(CONFIG.monitor, CONFIG.monitorScale) or term.current()

  local replyChannel = math.random(2000, 60000)
  modem.open(replyChannel)

  local S = {
    mode = "idle",   -- idle | checking | granted | denied | error
    since = 0,
    result = nil,
    pending = nil,
    openUntil = 0,
    frame = 0,
    sounds = {},
  }

  ------------------------------------------------------------------ hardware
  local function setDoor(open)
    if open then
      redstone.setOutput(CONFIG.redstoneSide, not CONFIG.defaultOutput)
    else
      redstone.setOutput(CONFIG.redstoneSide, CONFIG.defaultOutput)
    end
  end

  local function updateLamps()
    if CONFIG.lamps.granted then redstone.setOutput(CONFIG.lamps.granted, S.openUntil > 0) end
    if CONFIG.lamps.denied then redstone.setOutput(CONFIG.lamps.denied, S.mode == "denied") end
  end

  local function beep(delayMs, instrument, pitch)
    S.sounds[#S.sounds + 1] = { at = nowMs() + delayMs, inst = instrument, pitch = pitch }
  end

  local function runSounds()
    if #S.sounds == 0 then return end
    if not speaker then S.sounds = {}; return end
    local now, keep = nowMs(), {}
    for _, s in ipairs(S.sounds) do
      if s.at <= now then pcall(speaker.playNote, s.inst, 1, s.pitch) else keep[#keep + 1] = s end
    end
    S.sounds = keep
  end

  ------------------------------------------------------------------ drawing
  local function header(t, w)
    ui.fill(t, 1, 1, w, 1, colors.blue)
    ui.center(t, 1, CONFIG.title, colors.white, colors.blue)
  end

  local function usesText(r)
    if r.uses == -1 then return "Unlimited uses" end
    if r.uses == 0 then return "That was your last use" end
    return "Uses left: " .. r.uses
  end

  local function expText(r)
    if r.exp == 0 then return "No expiry" end
    return "Expires in " .. ui.duration((r.exp - nowMs()) / 1000)
  end

  local function drawBase()
    local t = screen
    local w, h = t.getSize()
    local mid = math.max(3, math.floor(h / 2))

    if S.mode == "idle" then
      ui.clear(t, colors.black)
      header(t, w)
      if w >= 20 and h >= 8 then ui.frame(t, 2, 3, w - 2, h - 4, nil, colors.gray, colors.black) end
      ui.center(t, mid - 1, "LOCKED", colors.red)
      ui.text(t, 2, h, "Door: " .. CONFIG.doorId, colors.gray)

    elseif S.mode == "checking" then
      ui.clear(t, colors.black)
      header(t, w)
      ui.center(t, mid - 1, "VERIFYING", colors.yellow)

    elseif S.mode == "granted" then
      local r = S.result
      ui.clear(t, colors.green)
      ui.center(t, mid - 2, "ACCESS GRANTED", colors.white, colors.green)
      ui.center(t, mid, r.name ~= "" and r.name or "Welcome", colors.white, colors.green)
      ui.center(t, mid + 1, usesText(r), colors.white, colors.green)
      ui.center(t, mid + 2, expText(r), colors.white, colors.green)

    elseif S.mode == "denied" then
      ui.clear(t, colors.red)
      ui.center(t, mid - 2, "ACCESS DENIED", colors.white, colors.red)
      local text = proto.REASONS[S.result.reason] or S.result.reason
      for i, line in ipairs(ui.wrap(text, math.max(10, w - 4))) do
        ui.center(t, mid + i - 1, line, colors.white, colors.red)
      end

    elseif S.mode == "error" then
      ui.clear(t, colors.orange)
      ui.center(t, mid - 2, "NO RESPONSE", colors.black, colors.orange)
      local text = proto.REASONS[S.result.reason] or S.result.reason
      for i, line in ipairs(ui.wrap(text, math.max(10, w - 4))) do
        ui.center(t, mid + i - 1, line, colors.black, colors.orange)
      end
    end
  end

  local function drawDynamic()
    local t = screen
    local w, h = t.getSize()
    local mid = math.max(3, math.floor(h / 2))

    if S.mode == "idle" then
      local dots = string.rep(".", S.frame % 4)
      local msg = "Present your card" .. dots
      msg = msg .. string.rep(" ", 20 - #msg)
      ui.text(t, math.floor((w - 20) / 2) + 1, mid + 1, msg, colors.white)
      ui.text(t, math.max(1, w - 8), h, os.date("%H:%M:%S"), colors.gray)

    elseif S.mode == "checking" then
      local elapsed = (nowMs() - S.since) / 1000
      ui.center(t, mid + 1, string.format("%s %4.1fs", ui.spinner(S.frame), elapsed), colors.white)

    elseif S.mode == "granted" then
      local total = CONFIG.openTime * 1000
      local remaining = math.max(0, S.openUntil - nowMs())
      ui.center(t, h - 2, string.format("Door open %2ds ", math.ceil(remaining / 1000)), colors.white, colors.green)
      ui.bar(t, 3, h - 1, math.max(1, w - 4), remaining / total, colors.white, colors.gray)
    end
  end

  local function setMode(mode, result)
    S.mode = mode
    S.result = result
    S.since = nowMs()
    updateLamps()
    drawBase()
    drawDynamic()
  end

  ------------------------------------------------------------------ logic
  local function send(req)
    modem.transmit(CONFIG.channel, replyChannel, req)
  end

  local function onCard(id, handle, backend)
    reader:release(backend, handle) -- take the card back out immediately
    if S.mode == "checking" then return end

    if id == false then
      beep(0, "bit", 8); beep(180, "bit", 8); beep(360, "bit", 5)
      setMode("denied", { reason = "invalid_card" })
      return
    end

    local req = proto.makeRequest(CONFIG.doorId, CONFIG.secret, id)
    S.pending = { req = req, started = nowMs(), retried = false, badSig = false }
    send(req)
    setMode("checking")
  end

  local function onModem(channel, msg)
    local p = S.pending
    if channel ~= replyChannel or not p then return end

    local ok, why = proto.checkResponse(msg, CONFIG.doorId, CONFIG.secret, p.req.nonce)
    if not ok then
      if why == "mac" then p.badSig = true end -- keep waiting; remembered for diagnostics
      return
    end

    S.pending = nil
    if msg.ok then
      S.openUntil = nowMs() + CONFIG.openTime * 1000
      setDoor(true)
      beep(0, "bit", 18); beep(120, "bit", 24)
      setMode("granted", msg)
    else
      beep(0, "bit", 8); beep(180, "bit", 8); beep(360, "bit", 5)
      setMode("denied", msg)
    end
  end

  local function onTick()
    S.frame = S.frame + 1
    local now = nowMs()
    runSounds()

    if S.openUntil > 0 and now >= S.openUntil then
      S.openUntil = 0
      setDoor(false)
      updateLamps()
      if S.mode == "granted" then setMode("idle"); return end
    end

    if (S.mode == "denied" or S.mode == "error") and now - S.since >= 3000 then
      setMode("idle")
      return
    end

    if S.mode == "checking" and S.pending then
      local p = S.pending
      local age = now - p.started
      if not p.retried and age > 1200 then
        p.retried = true
        send(p.req) -- same nonce: the server answers idempotently, no double use
      end
      if age > CONFIG.timeout * 1000 then
        S.pending = nil
        beep(0, "bit", 5); beep(250, "bit", 5)
        setMode("error", { reason = p.badSig and "bad_signature" or "no_response" })
        return
      end
    end

    drawDynamic()
  end

  ------------------------------------------------------------------ maintenance
  local function maintenanceMenu()
    local t = term.current()
    while true do
      ui.clear(t, colors.black)
      local w = t.getSize()
      ui.fill(t, 1, 1, w, 1, colors.blue)
      ui.text(t, 2, 1, "DOOR CONTROLLER | MAINTENANCE", colors.white, colors.blue)
      print("")
      print("Door ID: " .. CONFIG.doorId)
      print("Reader(s): " .. reader:describe())
      print("Modem: " .. (modem and "attached" or "missing"))
      print("Reply channel: " .. tostring(replyChannel))
      print("Server channel: " .. tostring(CONFIG.channel))
      print("Redstone output: " .. tostring(CONFIG.redstoneSide))
      print("Unlock duration: " .. tostring(CONFIG.openTime) .. "s")
      print("Monitor: " .. (screen ~= term.current() and "attached" or "terminal only"))
      print("")
      print("R) Reboot controller")
      print("Q) Return to access screen")
      while true do
        local ev, ch = os.pullEventRaw()
        if ev == "char" and (ch == "q" or ch == "Q") then
          screen = ui.findMonitor(CONFIG.monitor, CONFIG.monitorScale) or term.current()
          setMode("idle")
          return
        elseif ev == "char" and (ch == "r" or ch == "R") then
          setDoor(false)
          os.reboot()
        end
      end
    end
  end

  ------------------------------------------------------------------ run
  setDoor(false)
  updateLamps()
  reader:start()
  setMode("idle")
  print("Door '" .. CONFIG.doorId .. "' online. Readers: " .. reader:describe())

  local tick = os.startTimer(0.1)
  while true do
    local ev = { os.pullEventRaw() }
    local e = ev[1]
    if e == "timer" and ev[2] == tick then
      tick = os.startTimer(0.1)
      onTick()
    elseif e == "modem_message" then
      onModem(ev[3], ev[5])
    elseif e == "terminate" then
      -- Deliberately ignored; maintenance mode is the supported recovery path.
    elseif e == "char" and (ev[2] == "m" or ev[2] == "M") and S.mode == "idle" and not S.pending then
      maintenanceMenu()
    else
      local id, handle, backend = reader:poll(ev)
      if id ~= nil then onCard(id, handle, backend) end
    end
  end
end

local ok, err = pcall(main)
if not ok then
  pcall(redstone.setOutput, CONFIG.redstoneSide, CONFIG.defaultOutput)
  if CONFIG.lamps.granted then pcall(redstone.setOutput, CONFIG.lamps.granted, false) end
  if CONFIG.lamps.denied then pcall(redstone.setOutput, CONFIG.lamps.denied, false) end
  term.setBackgroundColor(colors.black)
  term.setTextColor(colors.red)
  term.clear()
  term.setCursorPos(1, 1)
  print("DOOR CONTROLLER STOPPED")
  printError(err)
  print("")
  print("Door output forced to the configured locked state.")
  print("Press R to reboot, or Q to leave it stopped.")
  while true do
    local ev, ch = os.pullEventRaw()
    if ev == "char" and (ch == "r" or ch == "R") then os.reboot() end
    if ev == "char" and (ch == "q" or ch == "Q") then return end
  end
end

end

local function runProbe(args)
-- tools/nfc_probe.lua
-- Lists attached peripherals whose type matches a substring (default "nfc")
-- together with their Lua methods. Read-only: nothing is written to any card.
--
--   nfc_probe            -> peripherals with "nfc" in their type
--   nfc_probe neo        -> any other substring
--   nfc_probe *          -> every peripheral

local match = (args[1] or "nfc"):lower()
local found = 0

for _, name in ipairs(peripheral.getNames()) do
  local ptype = peripheral.getType(name) or "?"
  if match == "*" or ptype:lower():find(match, 1, true) or name:lower():find(match, 1, true) then
    found = found + 1
    print(name .. "  [" .. ptype .. "]")
    for _, m in ipairs(peripheral.getMethods(name) or {}) do
      print("   " .. m)
    end
  end
end

if found == 0 then
  print("No peripheral matching '" .. match .. "'.")
  print("Try: nfc_probe *")
else
  print("")
  print("Classic Peripherals NFC uses type nfc_reader and nfc_data/nfc_write events.")
end

end

if ROLE == "server" then
  runServer()
elseif ROLE == "client" then
  runClient()
elseif ROLE == "nfc_probe" then
  runProbe({ ... })
else
  error('doorlock.lua: set ROLE to "server", "client" or "nfc_probe"', 0)
end
