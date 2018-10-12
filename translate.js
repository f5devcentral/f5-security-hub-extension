const account = require('./aws-account.json');

const severityMap = (severity) => {
    const sevmap = {
        "Informational": 0,
        "Critical": 90,
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

function affFromEvent(event) {

    const awsFinding = {
        SchemaVersion : '2018-09-21',
        ProductArn : `arn:aws:overbridge:us-east-1:${account.Account}:provider:private/default`,
        AwsAccountId : account.Account,
        Id: `us-east-1/${account.Account}/${new Date().getTime()}`,
        Types: [ { Namespace: 'Threat Detections' } ],
        CreatedAt: new Date(),
        UpdatedAt: new Date(),
        Severity: {
            Product: 5.5,
            Normalized: severityMap(event.severity),
        },
        Title: event.attack_type,
        Description: event.sig_names + ' ' + event.violations
        /*
        Network: {
            SourceIpV4: '1.2.3.4',
            SourcePort: 32002,
            DestinationIpV4: '4.3.2.1',
            DestinationPort: 80,
            Protocol: 'HTTP'
        }*/
    }
    //end AFF
    
    return { "Findings": [ awsFinding ] };
}
module.exports.affFromEvent = affFromEvent;
