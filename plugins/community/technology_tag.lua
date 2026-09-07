-- Community example: derive a bounded observation from existing event data.
-- This plugin makes no network request and cannot access files or processes.
local technology = event.data["technology"]
if technology ~= nil and technology ~= "" then
    add_asset("community_technology", technology)
end
