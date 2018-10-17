const net = require('net');
const { Transform } = require('stream');
const util = require('util');



class LineStream extends Transform {
    /**
       Ensures data recieved at next stream is broken by newline
    */
    constructor(opts, linebreak) {
        super(opts);
        this.linebreak = linebreak || '\n';
        this.buffer = '';
    }

    _transform(data, encoding, callback) {
        const input = this.buffer + data.toString('utf8');
        const lines = input.split(this.linebreak);
        this.buffer = lines.pop();
        while (lines.length > 0) {
            const line = lines.shift();
            this.push(line);
        }

        callback();
    }

    _flush(callback) {
        this.push(`${this.buffer}\n`);
        callback();
    }
}

const csv_fields =
[
    "attack_type",
    "blocking_exception_reason",
    "captcha_result",
    "client_type",
    "date_time",
    "dest_ip",
    "dest_port",
    "device_id",
    "geo_location",
    "http_class_name",
    "ip_address_intelligence",
    "ip_client",
    "ip_with_route_domain",
    "is_truncated",
    "login_result",
    "management_ip_address",
    "method",
    "mobile_application_name",
    "mobile_application_version",
    "policy_apply_date",
    "policy_name",
    "protocol",
    "query_string",
    "request",
    "request_status",
    "response",
    "response_code",
    "route_domain",
    "session_id",
    "severity",
    "sig_ids",
    "sig_names",
    "sig_set_names",
    "src_port",
    "staged_sig_ids",
    "staged_sig_names",
    "staged_sig_set_names",
    "sub_violations",
    "support_id",
    "unit_hostname",
    "uri",
    "username",
    "violation_details",
    "violation_rating",
    "violations",
    "virus_name",
    "websocket_direction",
    "websocket_message_type",
    "x_forwarded_for_header_value"
]


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

const csvParse = require('csv-parse/lib/sync');

class AsmToJson extends Transform {
    constructor(opts) {
        super(opts);
    }

    _transform(data, encoding, callback) {
        
        const csv_line = data.toString().split(' ASM:').slice(1).join('');
        if( csv_line ) {
            const input = `${csv_fields.join(',')}
${csv_line}
`
            const asm_json = csvParse(input, { columns: true });
            callback(null, JSON.stringify(asm_json[0]));
        } else {
            callback();
        }
    }
}

function AsmLogStream(socket) {
    return socket.pipe(new LineStream(null, '\r\n')).pipe(new AsmToJson());
}
module.exports.AsmLogStream = AsmLogStream;
