       
<#
.SYNOPSIS
    Retrieves Common Vulnerabilities and Exposures (CVE) information from the National Vulnerability Database (NVD) for the specified applications.
.DESCRIPTION
    The Get-NvdCve function retrieves CVE information from the NVD for the specified applications. It uses the NVD REST API to retrieve the information.
.PARAMETER applications
    Specifies the applications for which to retrieve CVE information. This parameter is mandatory.
.PARAMETER cvssV3Severity
    Specifies the Common Vulnerability Scoring System (CVSS) v3 severity level for which to retrieve CVE information. This parameter is optional. The default value is 'CRITICAL'.
.EXAMPLE
    $results = Get-NvdCveByApplication -applications "sitecore", "atlassian", "liferay", "telerik"
    Retrieves Critical CVE information for sitecore, atlassian, liferay, and telerik then outputs the results in the $results object.
.NOTES
    Uses the NVD REST API at the following URL to retrieve CVE information:
        https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:*:*:*:*:*:*:en
        https://services.nvd.nist.gov/rest/json/cves/2.0
    
    Currently the NVD REST API does not support retrieving CVE information for multiple applications in a single request. Therefore, if multiple applications are specified, the function will send a separate request to the NVD REST API for each application. To avoid overloading the NVD server, the function will wait 6 seconds between each request.
    
    This function currently hardcodes the following parameters:
        cvssV3Severity = Critical
#>

function Get-NvdCveByApplication {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$applications,
        [string]$cvssV3Severity = 'CRITICAL'
    )

    foreach ($app in $applications) {
        $cpe = "cpe:2.3:a:$($app):*" # Construct the Common Platform Enumeration (CPE) matching string for the application

        $url = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$app&cvssV3Severity=$cvssV3Severity" # Construct the URL for the NVD REST API

        $response = Invoke-RestMethod -Uri $url # Invoke the NVD REST API and retrieve the response
        $response # Output the response to the console

        if ($applications.count -gt 1) { Start-Sleep -Seconds 6 } # If retrieving CVE information for multiple applications, wait 6 seconds between each request to avoid overloading the NVD server
    }
}
