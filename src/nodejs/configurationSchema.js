const Ajv = require('ajv')
const ajv = new Ajv();

const schema = {
    title: 'Config',
    type: 'object',
    definitions: {
        FilterArray: {
            type: 'array',
            items: {
                type: 'object',
                required: [ 'Value', 'Comparison' ],
                additionalProperties: false,
                properties: {
                    Value: {
                        type: 'string',
                    },
                    Comparison: {
                        type: 'string',
                        enum: [ 'EQUALS', 'PREFIX', 'CONTAINS' ],
                    }
                }
            }
        }
    },
    required: [ 'Region', 'Filter' ],
    additionalProperties: false,
    properties: {
        Region: {
            type: 'string',
            description: 'AWS Region to send SecurityHub Findings to.',
            enum: [ 'us-west-2',
                    'us-east-1',
                    'us-west-1',
                    'ap-south-1',
                    'ap-northeast-2',
                    'ap-southeast-1',
                    'ap-southeast-2',
                    'ap-northeast-1',
                    'ca-central-1',
                    'eu-central-1',
                    'eu-west-1',
                    'eu-west-2',
                    'eu-west-3',
                    'sa-east-1',
                  ],
        },
        Filter: {
            type: 'object',
            properties: {
                attack_type: { "$ref": "#/definitions/FilterArray" },
                blocking_exception_reason: { "$ref": "#/definitions/FilterArray" },
                captcha_result: { "$ref": "#/definitions/FilterArray" },
                client_type: { "$ref": "#/definitions/FilterArray" },
                date_time: { "$ref": "#/definitions/FilterArray" },
                dest_ip: { "$ref": "#/definitions/FilterArray" },
                dest_port: { "$ref": "#/definitions/FilterArray" },
                device_id: { "$ref": "#/definitions/FilterArray" },
                geo_location: { "$ref": "#/definitions/FilterArray" },
                http_class_name: { "$ref": "#/definitions/FilterArray" },
                ip_address_intelligence: { "$ref": "#/definitions/FilterArray" },
                ip_client: { "$ref": "#/definitions/FilterArray" },
                ip_with_route_domain: { "$ref": "#/definitions/FilterArray" },
                is_truncated: { "$ref": "#/definitions/FilterArray" },
                login_result: { "$ref": "#/definitions/FilterArray" },
                management_ip_address: { "$ref": "#/definitions/FilterArray" },
                method: { "$ref": "#/definitions/FilterArray" },
                mobile_application_name: { "$ref": "#/definitions/FilterArray" },
                mobile_application_version: { "$ref": "#/definitions/FilterArray" },
                policy_apply_date: { "$ref": "#/definitions/FilterArray" },
                policy_name: { "$ref": "#/definitions/FilterArray" },
                protocol: { "$ref": "#/definitions/FilterArray" },
                query_string: { "$ref": "#/definitions/FilterArray" },
                request: { "$ref": "#/definitions/FilterArray" },
                request_status: { "$ref": "#/definitions/FilterArray" },
                response: { "$ref": "#/definitions/FilterArray" },
                response_code: { "$ref": "#/definitions/FilterArray" },
                route_domain: { "$ref": "#/definitions/FilterArray" },
                session_id: { "$ref": "#/definitions/FilterArray" },
                severity: { "$ref": "#/definitions/FilterArray" },
                sig_ids: { "$ref": "#/definitions/FilterArray" },
                sig_names: { "$ref": "#/definitions/FilterArray" },
                sig_set_names: { "$ref": "#/definitions/FilterArray" },
                src_port: { "$ref": "#/definitions/FilterArray" },
                staged_sig_ids: { "$ref": "#/definitions/FilterArray" },
                staged_sig_names: { "$ref": "#/definitions/FilterArray" },
                staged_sig_set_names: { "$ref": "#/definitions/FilterArray" },
                sub_violations: { "$ref": "#/definitions/FilterArray" },
                support_id: { "$ref": "#/definitions/FilterArray" },
                unit_hostname: { "$ref": "#/definitions/FilterArray" },
                uri: { "$ref": "#/definitions/FilterArray" },
                username: { "$ref": "#/definitions/FilterArray" },
                violation_details: { "$ref": "#/definitions/FilterArray" },
                violation_rating: { "$ref": "#/definitions/FilterArray" },
                violations: { "$ref": "#/definitions/FilterArray" },
                virus_name: { "$ref": "#/definitions/FilterArray" },
                websocket_direction: { "$ref": "#/definitions/FilterArray" },
                websocket_message_ty: { "$ref": "#/definitions/FilterArray" },
            }
        }
    }
}

schema['$id'] = 'foo';
schema['$schema'] = 'http://json-schema.org/draft-07/schema#';

module.exports.schema = schema;

const validate = ajv.compile(schema);
module.exports.validate = validate;

const errors = () => {
    return validate.errors;
};
module.exports.errors = errors;
