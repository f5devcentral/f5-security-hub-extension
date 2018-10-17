const account = require('./aws-account.json');

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

function affFromEvent(event) {

    const awsFinding = {
        SchemaVersion : '2018-10-08',
        ProductArn : `arn:aws:overbridge:us-east-1:${account.Account}:provider:private/default`,
        AwsAccountId : account.Account,
        Id: `us-east-1/${account.Account}/${new Date().getTime()}`,
        Types: [ 'Threat Detections', 'Unusual Behaviors' ],
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
