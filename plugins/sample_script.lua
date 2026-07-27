-- Sample Enumscan Lua Plugin
-- Checks target HTTP endpoint and reports findings

local target = event.target
local res = http_get(target)

if res and res.status == 200 then
    add_finding({
        title = "HTTP 200 OK Response",
        severity = "info",
        evidence = "Status 200 returned for target " .. target
    })
end
