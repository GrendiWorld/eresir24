# ?? GameSense API Guide

## ?? Documentation
**Official:** https://docs.gamesense.gs/

## ?? API Endpoint
**Base URL:** `https://eresir24.onrender.com`

## ? Public API Endpoints

### 1. Add/Update Config
**Endpoint:** `POST /api/config/add`

```lua
local http = require("gamesense/http")
local json = require("gamesense/json")

local config_name = "myconfig"
local config_data = "your config content here"

http.post("https://eresir24.onrender.com/api/config/add", {
    headers = {["Content-Type"] = "application/json"},
    body = json.stringify({name = config_name, config_data = config_data})
}, function(success, response)
    if success then
        local data = json.parse(response.body)
        if data.success then
            print("? Config saved:", data.message)
        end
    end
end)
```

### 2. Get All Configs
**Endpoint:** `GET /api/configs`

```lua
local http = require("gamesense/http")
local json = require("gamesense/json")

http.get("https://eresir24.onrender.com/api/configs", function(success, response)
    if success then
        local configs = json.parse(response.body)
        print("Found " .. #configs .. " configs:")
        for i, config in ipairs(configs) do
            print("Config " .. i .. ": " .. config.name)
        end
    end
end)
```

### 3. Get Config by Name
**Endpoint:** `GET /api/config/<config_name>`

```lua
local http = require("gamesense/http")

local config_name = "myconfig"

http.get("https://eresir24.onrender.com/api/config/" .. config_name, function(success, response)
    if success then
        local config_content = response.body
        print("? Config loaded:", config_content)
    end
end)
```

## ?? Important Notes

### Rate Limiting
- Maximum **1 request per 10 seconds** per IP address
- Returns HTTP 429 if exceeded

### Reserved Names
Cannot use: `cloud-config`, `cloud-configs`, `active-media`, `admins`, `add`, `configs`, `api`, `admin`, `login`, `logout`, `dashboard`, `static`, `templates`

### Data Format
- Config content can be any format: JSON, YAML, text, Lua code, etc.
- API stores and returns data as-is

## ?? Links

- **API Documentation:** https://eresir24.onrender.com/api-docs
- **GameSense Docs:** https://docs.gamesense.gs/
