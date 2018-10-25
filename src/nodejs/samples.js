
const { listFindings, importFindings, describeFindings } = require('./f5_overbridge.js');

const account = require('./aws-account.json');

const sample_01 = {
    SchemaVersion : '2018-10-08',
    ProductArn : `arn:aws:overbridge:us-east-1:${account.Account}:provider:private/default`,
    AwsAccountId : account.Account,
    Id: `us-east-1/${account.Account}/${new Date().getTime()}/1`,
    Types: [ 'Threat Detections' ],
    CreatedAt: new Date(),
    UpdatedAt: new Date(),
    Severity: {
        Product: 5.5,
        Normalized: 75
    },
    Title: 'Sample 01',
    Description: 'Sample Using Network property',
    GeneratorId: 'f5-asm-test',
    Network: {
        SourceIpV4: '1.2.3.4',
        SourcePort: 32002,
        DestinationIpV4: '4.3.2.1',
        DestinationPort: 80,
        Protocol: 'TCP'
    },
    Resources: [{
        Type: 'BIG-IP',
        Id: 'i-bedead'
    }]
}

const sample_02 = {
    SchemaVersion : '2018-10-08',
    ProductArn : `arn:aws:overbridge:us-east-1:${account.Account}:provider:private/default`,
    AwsAccountId : account.Account,
    Id: `us-east-1/${account.Account}/${new Date().getTime()}/2`,
    Types: [ 'Threat Detections' ],
    CreatedAt: new Date(),
    UpdatedAt: new Date(),
    Severity: {
        Product: 5.5,
        Normalized: 75
    },
    Title: 'Sample 01',
    Description: 'Sample Using Network property',
    GeneratorId: 'f5-asm-test',
    Network: {
        SourceIpV4: '1.2.3.4',
        SourcePort: 32002,
        DestinationIpV4: '4.3.2.1',
        DestinationPort: 80,
        Protocol: 'TCP'
    },
    Resources: [{
        Type: 'BIG-IP',
        Id: 'i-bedead'
    }]
}


const op = process.argv.pop();

if (op === 'list') {

    const thisAccount = {
        AwsAccountId: [{
            Value: account.Account,
            Comparison: 'EQUALS'
        }]
    };

    const byTitle = {
        Description: [{
            Value: 'Vulnerability',
            Comparison: 'CONTAINS'
        }]
    };

    listFindings(thisAccount).then((data) => {
        //listFindings(byTitle).then((data) => {
        console.log(require('util').inspect(data, {depth:null}));
    });
} else {
    const findingsArray = [ sample_01, sample_02 ]
    
    console.log(findingsArray);

    importFindings({
        Findings: findingsArray
    }).then((data) => {
        console.log(data);
    });
}
