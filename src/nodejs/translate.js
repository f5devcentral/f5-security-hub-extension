const account = { Account: '111111111111', Region: 'us-east-1' };

const setAccount = (data) => {
    account.Account = data.Account;
};
module.exports.setAccount = setAccount;

const setRegion = (region) => {
    account.Region = region;
}
module.exports.setRegion = setRegion;

const severityMap = (severity) => {
    const sevmap = {
        "Informational": 0,
        "Warning": 25,
        "Critical": 75,
        "Error": 100
    };
    if (sevmap[severity] !== undefined) return sevmap[severity]
    else return 99;
};

const aff_namespace_enum = [ "Software and Configuration Checks",
                             "Threat Detections",
                             "Effects",
                             "Unusual Behaviors",
                             "Sensitive Data Identifications" ]
const typeMapping = [
    { attack_type: 'Buffer overflow',
      affType: 'Effects/Denial of Service',
      description: 'Buffer overflow exploits are attacks that alter the flow on an application by overwriting parts of memory.' },
    { attack_type: 'Directory indexing',
      affType: 'Threat Detections/Discovery',
      description: 'Automatic directory listing/indexing is a web server function that lists all of the files within a requested directory if the normal base file is not present.' },
    { attack_type: 'Authentication/authorization attacks',
      affType: 'Threat Detections/Credential Access',
      description: 'Authentication section covers attacks that target a website\'s method of validating the identity of a user, service, or application. Authorization section covers attacks that target a website\'s method of determining if a user, service, or application has the necessary permissions to perform a requested action.' },
    { attack_type: 'Information leakage',
      affType: 'Effects/Data Exposure',
      description: 'Information leakage is when a website reveals sensitive data, such as developer comments or error messages, which may aid an attacker in exploiting the system.' },
    { attack_type: 'Predictable resource location',
      affType: 'Threat Detections/Discovery',
      description: 'Predictable resource location is an attack technique used to uncover hidden website content and functionality.' },
    { attack_type: 'Command execution',
      affType: 'Threat Detections/Execution',
      description: 'Command execution attacks are those where an attacker manipulates the data for a user-input field by submitting commands with the intent of altering the web page content or web application, with the intent of executing a shell command on a remote server to reveal sensitive data for example, a list of users on a server.' },
    { attack_type: 'Vulnerability scan',
      affType: 'Threat Detections/Discovery',
      description: 'A vulnerability scan is an attack technique that uses an automated security program to probe a web application for software vulnerabilities.' },
    { attack_type: 'Brute force',
      affType: 'Threat Detections/Credential Access',
      description: 'Brute force attack is an outside attempt by hackers to access post-logon pages of a website by guessing usernames and passwords; brute force attacks are performed when a malicious user attempts to log on to a URL numerous times, running many combinations of usernames and passwords until the user successfully logs on.' },
    { attack_type: 'Denial of Service',
      affType: 'Effects/Denial of Service',
      description: 'Denial of service (DoS) is an attack technique that overwhelms system resources to prevent a web site from serving normal user activity.' },
    { attack_type: 'Trojan/Backdoor/Spyware',
      affType: 'Threat Detections/Execution',
      description: 'Attackers use Trojan horse, backdoor, and spyware attacks to try to circumvent a web servers or web applications built-in security by masking the attack within a legitimate communication. For example, an attacker may include an attack in an email or Microsoft Word document, and when a user opens the email or document, the attack launches.' },
    { attack_type: 'Other application attacks',
      affType: 'Unusual Behaviors/Application',
      description: 'This attack category represents attacks that do not fit into the more explicit attack classifications.' },
    { attack_type: 'Abuse of functionality',
      affType: 'Threat Detections/Privilege Escalation',
      description: 'Abuse of functionality is an attack technique that uses a website\'s own features and functionality to consume, defraud, or circumvent the applications access control mechanisms.' },
    { attack_type: 'Cross-site scripting (XSS)',
      affType: 'Threat Detections/Execution',
      description: 'Cross-site scripting (XSS) is an attack technique that forces a website to echo attacker-supplied executable code, which loads in a user\'s browser.' },
    { attack_type: 'Server-side code injection',
      affType: 'Threat Detections/Execution',
      description: 'SSI injection (server-side include) is a server-side exploit technique that allows an attacker to send code into a web application, which is then run locally by the web server.' },
    { attack_type: 'SQL injection',
      affType: 'Threat Detections/Execution',
      description: 'SQL Injection is an attack technique used to exploit websites that construct SQL statements from user-supplied input.' },
    { attack_type: 'Detection evasion',
      affType: 'Threat Detections/Defense Evasion',
      description: 'Detection evasion is an attack technique that attempts to disguise or hide an attack to avoid detection by an attack signature.' },
    { attack_type: 'Path traversal',
      affType: 'Threat Detections/Initial Access',
      description: 'The path traversal attack technique forces access to files, directories, and commands that potentially reside outside the web document root directory.' },
    { attack_type: 'LDAP injection',
      affType: 'Threat Detections/Execution',
      description: 'LDAP injection is an attack technique used to exploit web sites that construct LDAP statements from user-supplied input.' },
    { attack_type: 'Forceful Browsing',
      affType: 'Threat Detections/Initial Access',
      description: 'Forceful Browsing attacks attempt to access data outside the specific access schema of the application.' },
    { attack_type: 'HTTP parser attack',
      affType: 'Unusual Behaviors/Application',
      description: 'HTTP parser attacks attempt to execute malicious code, extract information, or enact Denial of Service by targeting the HTTP parser directly.' },
    { attack_type: 'HTTP Request Smuggling',
      affType: 'Unusual Behaviors/Application',
      description: 'HTTP Request Smuggling attacks attempt to encapsulate one request within another request through a web proxy.' },
    { attack_type: 'HTTP Response Splitting',
      affType: 'Unusual Behaviors/Application',
      description: 'HTTP Response Splitting attacks attempt to manipulating the server into inject a CR/LF sequence in its response headers.' },
    { attack_type: 'Injection Attempt',
      affType: 'Threat Detections/Initial Access',
      description: 'Injection Attempt attacks exploit weakness in various other applications in order to inject and/or execute malicious code.' },
    { attack_type: 'Malicious File Upload',
      affType: 'Threat Detections/Execution',
      description: 'Malicious File Upload attacks attempt to exploit services by uploading files that may contain malicious code.' },
    { attack_type: 'Non-browser Client',
      affType: 'Threat Detections/Initial Access',
      description: 'Non Browser Client attacks use crawlers or other scripts to simulate human activity.' },
    { attack_type: 'Other application activity',
      affType: 'Unusual Behaviors/Application',
      description: 'This attack category represents attacks that do not fit into the more explicit attack classifications.' },
    { attack_type: 'Parameter tampering',
      affType: 'Threat Detections/Initial Access',
      description: 'Parameter Tampering attacks attempt to manipulate and capture data by modifying parameters in HTTP query strings.' },
    { attack_type: 'Remote file include',
      affType: 'Threat Detections/Execution',
      description: 'Remote file location attacks attempt to exploit web applications that may retrieve and execute the code included in remote files.' },
    { attack_type: 'Server side code injection',
      affType: 'Threat Detections/Execution',
      description: 'Server side code injection attempts to exploit weakness in applications and services to force those services to execute malicous code.' },
    { attack_type: 'Session Hijacking',
      affType: 'Threat Detections/Privilege Escalation',
      description: 'Session hijacking attacks attempt to hijack a valid extant user session.' },
    { attack_type: 'Web Scraping',
      affType: 'Unusual Behaviors/User',
      description: 'Web scraping attacks simulate human exploration of the Web to harvest site information.' },
    { attack_type: 'XML Parser Attack',
      affType: 'Threat Detections/Execution',
      description: 'XML parser attacks attempt execute malicious code or enact a Denial of Service by targeting the XML parser directly.' },
    { attack_type: 'XPath Injection',
      affType: 'Threat Detections/Execution',
      description: 'XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents.' }
];

function getEventType(event) {
    const asmtype = typeMapping.filter(x => event === x.attack_type).map(x => x.affType);
    return [ 'Threat Detections', 'Effects', 'Unusual Behaviors' ]
        .map(x => {
            if( asmtype[0] && asmtype[0].indexOf(x) === 0 ) return asmtype[0];
            else return x;
        });

}

function affFromEvent(event) {

    const specificEventTypes = getEventType(event);

    const awsFinding = {
        SchemaVersion : '2018-10-08',
        ProductArn : `arn:aws:overbridge:us-east-1:${account.Account}:provider:private/default`,
        AwsAccountId : account.Account,
        Id: `us-east-1/${account.Account}/${new Date().getTime()}`,
        Types: getEventType(event.attack_type),
        CreatedAt: new Date(event.date_time),
        UpdatedAt: new Date(),
        Severity: {
            Product: 5.5,
            Normalized: severityMap(event.severity),
        },
        Title: event.sig_names,
        Description: event.attack_type + ' - ' + event.violations,
        GeneratorId: 'tm:security:profile:application',
        Network: {
            SourceIpV4: event.ip_client,
            SourcePort: parseInt(event.src_port),
            DestinationIpV4: event.dest_ip,
            DestinationPort: parseInt(event.dest_port),
            Protocol: event.protocol
        },
        Resources: [{
            Type: 'F5-BIG-IP',
            Id: event.unit_hostname
        }],
        ProductFields: event
    }
    //end AFF
    
    return { "Findings": [ awsFinding ] };
}
module.exports.affFromEvent = affFromEvent;
