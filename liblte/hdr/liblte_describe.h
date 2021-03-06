#ifndef __LIBLTE_DESC_H__
#define __LIBLTE_DESC_H__

#include <climits>
#include <iomanip>
#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include "liblte_common.h"
#include "liblte_mme.h"

// Helper function to stream out hex value
namespace detail {
constexpr int HEX_DIGIT_BITS = 4;  // One hex digit = 4bits

template <typename T>
struct is_char
    : std::integral_constant<bool, std::is_same<T, char>::value ||
                                       std::is_same<T, signed char>::value ||
                                       std::is_same<T, unsigned char>::value> {
};
}

template <typename T>
std::string hex_out_s(T val) {
  using namespace detail;

  std::stringstream sformatter;
  sformatter << std::hex << std::internal << std::setfill('0')
             << std::setw(sizeof(T) * CHAR_BIT / HEX_DIGIT_BITS)
             << (is_char<T>::value ? static_cast<int>(val) : val);

  return sformatter.str();
}

constexpr int indent_size = 4;
// TOP api get string representation of mme msg

std::string liblte_mme_msg_to_string(LIBLTE_BYTE_MSG_STRUCT &mme_msg);

// Protocol Discriminator
static const std::map<int, std::string> pd_strings{
    {LIBLTE_MME_PD_EPS_SESSION_MANAGEMENT, "EPS  Session Management"},
    {LIBLTE_MME_PD_EPS_MOBILITY_MANAGEMENT, "EPS Mobility Management"}};

void set_pd(uint8 eps_pd, std::ostream &ostream, const std::string &indent);

// Security Header Type
static const std::map<int, std::string> securiy_header_type_strings{
    {LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS,
     "Plain NAS message, not security protected"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY, "Integrity protected"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED,
     "Integrity protected and ciphered"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT,
     "Integrity protected with new EPS security context"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT,
     "Integrity protected and ciphered with new EPS security context"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_PARTIALLY_CIPHERED,
     "Integrity protected and partially ciphered NAS message"},
    {LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST,
     "Securiy header for the SERVICE REQUEST message"}};

void set_sec_hdr_type(uint8 sec_hdr_type, std::ostream &ostream,
                      const std::string &indent);

// Message Type
static const std::map<int, std::string> message_type_strings{
    {LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST, "Attach request"},
    {LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT, "Attach accept"},
    {LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE, "Attach complete"},
    {LIBLTE_MME_MSG_TYPE_ATTACH_REJECT, "Attach reject"},
    {LIBLTE_MME_MSG_TYPE_DETACH_REQUEST, "Detach request"},
    {LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT, "Detach accept"},
    {LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REQUEST,
     "Tracking area update request"},
    {LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT,
     "Tracking area update accept"},
    {LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_COMPLETE,
     "Tracking area update complete"},
    {LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT,
     "Tracking area update reject"},
    {LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST, "Extended service request"},
    {LIBLTE_MME_MSG_TYPE_CONTROL_PLANE_SERVICE_REQUEST,
     "Control plane service request"},
    {LIBLTE_MME_MSG_TYPE_SERVICE_REJECT, "Service reject"},
    {LIBLTE_MME_MSG_TYPE_SERVICE_ACCEPT, "Service accept"},
    {LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND,
     "GUTI reallocation command"},
    {LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMPLETE,
     "GUTI reallocation complete"},
    {LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST, "Authentication request"},
    {LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE, "Authentication response"},
    {LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT, "Authentication reject"},
    {LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE, "Authentication failure"},
    {LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST, "Identity request"},
    {LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE, "Identity response"},
    {LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND, "Security mode command"},
    {LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE, "Security mode complete"},
    {LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT, "Security mode reject"},
    {LIBLTE_MME_MSG_TYPE_EMM_STATUS, "EMM status"},
    {LIBLTE_MME_MSG_TYPE_EMM_INFORMATION, "EMM information"},
    {LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT, "Downlink NAS transport"},
    {LIBLTE_MME_MSG_TYPE_UPLINK_NAS_TRANSPORT, "Uplink NAS transport"},
    {LIBLTE_MME_MSG_TYPE_CS_SERVICE_NOTIFICATION, "CS Service notification"},
    {LIBLTE_MME_MSG_TYPE_DOWNLINK_GENERIC_NAS_TRANSPORT,
     "Downlink generic NAS transport"},
    {LIBLTE_MME_MSG_TYPE_UPLINK_GENERIC_NAS_TRANSPORT,
     "Uplink generic NAS transport"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST,
     "Activate default EPS bearer context request"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT,
     "Activate default EPS bearer context accept"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT,
     "Activate default EPS bearer context reject"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST,
     "Activate dedicated EPS bearer context request"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT,
     "Activate dedicated EPS bearer context accept"},
    {LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT,
     "Activate dedicated EPS bearer context reject"},
    {LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST,
     "Modify EPS bearer context request"},
    {LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_ACCEPT,
     "Modify EPS bearer context accept"},
    {LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REJECT,
     "Modify EPS bearer context reject"},
    {LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST,
     "Deactivate EPS bearer context request"},
    {LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT,
     "Deactivate EPS bearer context accept"},
    {LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST, "PDN connectivity request"},
    {LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT, "PDN connectivity reject"},
    {LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REQUEST, "PDN disconnect request"},
    {LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT, "PDN disconnect reject"},
    {LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REQUEST,
     "Bearer resource allocation request"},
    {LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT,
     "Bearer resource allocation reject"},
    {LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REQUEST,
     "Bearer resource modification request"},
    {LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT,
     "Bearer resource modification reject"},
    {LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST, "ESM information request"},
    {LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE, "ESM information response"},
    {LIBLTE_MME_MSG_TYPE_NOTIFICATION, "Notification"},
    {LIBLTE_MME_MSG_TYPE_ESM_STATUS, "ESM status"},
    {LIBLTE_MME_MSG_TYPE_ESM_DATA_TRANSPORT, "ESM data transport"}};

void set_msg_type(uint8 msg_type, std::ostream &ostream,
                  const std::string &indent);

// Message Auth code
void set_mac(uint8 *mac, std::ostream &ostream, const std::string &indent);

// Sequence number
void set_seq_num(uint8 seq_num, std::ostream &ostream,
                 const std::string &indent);

// EPS bearer id
void set_eps_bearer_id(uint8 eps_bearer_id, std::ostream &ostream,
                       const std::string &indent);

// Procedure transaction id
void set_proc_transaction_id(uint8 proc_transaction_id, std::ostream &ostream,
                             const std::string &indent);
// Attach type
static const std::map<int, std::string> attach_type_strings{
    {1, "EPS attach"},
    {2, "combined EPS/IMSI attach"},
    {6, "EPS emergency attach"}};

// EPS attach type
void set_attach_type(uint8 attach_type, std::ostream &ostream,
                     const std::string &indent);

// NAS key set identifier
void set_nas_key_set_identifier(const LIBLTE_MME_NAS_KEY_SET_ID_STRUCT &nas_ksi,
                                std::ostream &ostream,
                                const std::string &indent);

void set_guti(const LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT &guti,
              std::ostream &ostream, const std::string &indent);

void set_imsi(const uint8 *imsi, std::ostream &ostream,
              const std::string &indent);

void set_imei(const uint8 *imei, std::ostream &ostream,
              const std::string &indent);

void set_imeisv(const uint8 *imeisv, std::ostream &ostream,
                const std::string &indent);

void set_tmgi(const LIBLTE_MME_MOBILE_ID_TMGI_STRUCT &tmgi,
              std::ostream &ostream, const std::string &indent);
// EPS mobile identity
void set_eps_mobile_id(const LIBLTE_MME_EPS_MOBILE_ID_STRUCT &eps_mobile_id,
                       std::ostream &ostream, const std::string &indent);

// UE network capability
void set_ue_network_cap(
    const LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT &ue_network_cap,
    std::ostream &ostream, const std::string &indent);

// ESM message container
void set_esm_message_container(LIBLTE_BYTE_MSG_STRUCT *esm_msg,
                               std::ostream &ostream,
                               const std::string &indent);

// PDN Connectivity Request
static const std::map<int, std::string> pdn_type_strings = {
    {LIBLTE_MME_PDN_TYPE_IPV4, "IPv4"},
    {LIBLTE_MME_PDN_TYPE_IPV6, "IPv6"},
    {LIBLTE_MME_PDN_TYPE_UNUSED, "unused"},
    {LIBLTE_MME_PDN_TYPE_NONIP, "non IP"}};

void set_pdn_type(uint8 pdn_type, std::ostream &ostream,
                  const std::string &indent);

void set_pdn_connectivity_request(
    const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT &pdn_con_req,
    std::ostream &ostream, const std::string &indent);

static const std::map<int, std::string> emm_cause_strings = {
    {LIBLTE_MME_EMM_CAUSE_IMSI_UNKNOWN_IN_HSS, "IMSI Unknown in HSS"},
    {LIBLTE_MME_EMM_CAUSE_ILLEGAL_UE, "Illegal UE"},
    {LIBLTE_MME_EMM_CAUSE_IMEI_NOT_ACCEPTED, "IMEI not accepted"},
    {LIBLTE_MME_EMM_CAUSE_ILLEGAL_ME, "Illegal ME"},
    {LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED, "EPS services not allowed"},
    {LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED,
     "EPS services and non-EPS services not allowed"},
    {LIBLTE_MME_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK,
     "UE identity cannot be derived by the network"},
    {LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED, "Implicitly detached"},
    {LIBLTE_MME_EMM_CAUSE_PLMN_NOT_ALLOWED, "PLMN not allowed"},
    {LIBLTE_MME_EMM_CAUSE_TRACKING_AREA_NOT_ALLOWED,
     "Tracking Area not allowed"},
    {LIBLTE_MME_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA,
     "Roaming not allowed in this tracking area"},
    {LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN,
     "EPS services not allowed in this PLMN"},
    {LIBLTE_MME_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA,
     "No Suitable Cells In tracking area"},
    {LIBLTE_MME_EMM_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE,
     "MSC temporarily not reachable"},
    {LIBLTE_MME_EMM_CAUSE_NETWORK_FAILURE, "Network failure"},
    {LIBLTE_MME_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE, "CS domain not available"},
    {LIBLTE_MME_EMM_CAUSE_ESM_FAILURE, "ESM failure"},
    {LIBLTE_MME_EMM_CAUSE_MAC_FAILURE, "MAC failure"},
    {LIBLTE_MME_EMM_CAUSE_SYNCH_FAILURE, "Synch failure"},
    {LIBLTE_MME_EMM_CAUSE_CONGESTION, "Congestion"},
    {LIBLTE_MME_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH,
     "UE security capability mismatch"},
    {LIBLTE_MME_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED,
     "Security mode rejected, unspecified"},
    {LIBLTE_MME_EMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CSG,
     "Not authorized for this CSG"},
    {LIBLTE_MME_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE,
     "Non-EPS authentication unacceptale"},
    {LIBLTE_MME_EMM_CAUSE_CS_SERVICE_TEMPORARILY_NOT_AVAILABLE,
     "CS service temporarily not available"},
    {LIBLTE_MME_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED,
     "No EPS bearer context activated"},
    {LIBLTE_MME_EMM_CAUSE_SEVERE_NETWORK_FAILURE, "Severe network failure"},
    {LIBLTE_MME_EMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE,
     "Semantically incorrect message"},
    {LIBLTE_MME_EMM_CAUSE_INVALID_MANDATORY_INFORMATION,
     "Invalid mandatory information"},
    {LIBLTE_MME_EMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED,
     "Message type non-existent or not implemented"},
    {LIBLTE_MME_EMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE,
     "Message type not compatible with the protocol state"},
    {LIBLTE_MME_EMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED,
     "Information element non-existent or not implemented"},
    {LIBLTE_MME_EMM_CAUSE_CONDITIONAL_IE_ERROR, "Conditional IE error"},
    {LIBLTE_MME_EMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE,
     "Message not compatible with the protocol state"},
    {LIBLTE_MME_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
     "Protocol error, unspecified"}};
void set_emm_cause(uint8 emm_cause, std::ostream &ostream,
                   const std::string &indent);

static const std::map<int, std::string> esm_cause_strings = {
    {LIBLTE_MME_ESM_CAUSE_OPERATOR_DETERMINED_BARRING,
     "Operator Determined Barring"},
    {LIBLTE_MME_ESM_CAUSE_INSUFFICIENT_RESOURCES, "Insufficient resource"},
    {LIBLTE_MME_ESM_CAUSE_UNKNOWN_OR_MISSING_APN, "Missing or Unknown APN"},
    {LIBLTE_MME_ESM_CAUSE_UNKNOWN_PDN_TYPE, "Unknown PDN type"},
    {LIBLTE_MME_ESM_CAUSE_USER_AUTHENTICATION_FAILED,
     "User authentication failed"},
    {LIBLTE_MME_ESM_CAUSE_REQUEST_REJECTED_BY_SERVING_OR_PDN_GW,
     "Request rejected by Serving GW or PDN GW"},
    {LIBLTE_MME_ESM_CAUSE_REQUEST_REJECTED_UNSPECIFIED,
     "Request rejected, unspecified"},
    {LIBLTE_MME_ESM_CAUSE_SERVICE_OPTION_NOT_SUPPORTED,
     "Service option not surpported"},
    {LIBLTE_MME_ESM_CAUSE_REQUESTED_SERVICE_OPTION_NOT_SUBSCRIBED,
     "Requested service option not subscribed"},
    {LIBLTE_MME_ESM_CAUSE_SERVICE_OPTION_TEMPORARILY_OUT_OF_ORDER,
     "Service option temporarily out of order"},
    {LIBLTE_MME_ESM_CAUSE_PTI_ALREADY_IN_USE, "PTI already in use"},
    {LIBLTE_MME_ESM_CAUSE_REGULAR_DEACTIVATION, "Regular deactivation"},
    {LIBLTE_MME_ESM_CAUSE_EPS_QOS_NOT_ACCEPTED, "EPS QoS not accepted"},
    {LIBLTE_MME_ESM_CAUSE_NETWORK_FAILURE, "Network failure"},
    {LIBLTE_MME_ESM_CAUSE_REACTIVATION_REQUESTED, "Reactivation requested"},
    {LIBLTE_MME_ESM_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
     "Semantic error in the TFT operation"},
    {LIBLTE_MME_ESM_CAUSE_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION,
     "Syntactical error in the TFT operation"},
    {LIBLTE_MME_ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY,
     "Invalid EPS bearer identity"},
    {LIBLTE_MME_ESM_CAUSE_SEMANTIC_ERRORS_IN_PACKET_FILTERS,
     "Semantic errors in packet filter(s)"},
    {LIBLTE_MME_ESM_CAUSE_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS,
     "Syntactical errors in packet filter(s)"},
    {LIBLTE_MME_ESM_CAUSE_UNUSED, "Unused"},
    {LIBLTE_MME_ESM_CAUSE_PTI_MISMATCH, "PTI mismatch"},
    {LIBLTE_MME_ESM_CAUSE_LAST_PDN_DISCONNECTION_NOT_ALLOWED,
     "Lst PDN disconnection not allowed"},
    {LIBLTE_MME_ESM_CAUSE_PDN_TYPE_IPV4_ONLY_ALLOWED,
     "PDN type IPv4 only allowed"},
    {LIBLTE_MME_ESM_CAUSE_PDN_TYPE_IPV6_ONLY_ALLOWED,
     "PDN type IPv6 only allowed"},
    {LIBLTE_MME_ESM_CAUSE_SINGLE_ADDRESS_BEARERS_ONLY_ALLOWED,
     "Single address bearers only allowed"},
    {LIBLTE_MME_ESM_CAUSE_ESM_INFORMATION_NOT_RECEIVED,
     "ESM information not received"},
    {LIBLTE_MME_ESM_CAUSE_PDN_CONNECTION_DOES_NOT_EXIST,
     "PDN connection does not exist"},
    {LIBLTE_MME_ESM_CAUSE_MULTIPLE_PDN_CONNECTIONS_FOR_A_GIVEN_APN_NOT_ALLOWED,
     "Multiple PDN connections for a given APN not allowed"},
    {LIBLTE_MME_ESM_CAUSE_COLLISION_WITH_NETWORK_INITIATED_REQUEST,
     "Collision with network initiated request"},
    {LIBLTE_MME_ESM_CAUSE_UNSUPPORTED_QCI_VALUE, "Unspported QCI value"},
    {LIBLTE_MME_ESM_CAUSE_BEARER_HANDLING_NOT_SUPPORTED,
     "Bearer handling not supported"},
    {LIBLTE_MME_ESM_CAUSE_MAXIMUM_EPS_BEARERS_REACHED,
     "Maximum number of EPS bearers reached"},
    {LIBLTE_MME_ESM_CAUSE_REQUESTED_APN_NOT_SUPPORTED,
     "Requested APN not supported in current RAT and PLMN combination"},
    {LIBLTE_MME_ESM_CAUSE_INVALID_PTI_VALUE, "Invalid PTI value"},
    {LIBLTE_MME_ESM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE,
     "Semantically incorrect message"},
    {LIBLTE_MME_ESM_CAUSE_INVALID_MANDATORY_INFORMATION,
     "Invalid mandatory information"},
    {LIBLTE_MME_ESM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED,
     "Message type non-existent or not implemented"},
    {LIBLTE_MME_ESM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE,
     "message type not compatible with the protocol state"},
    {LIBLTE_MME_ESM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED,
     "information element not-existent or not implemented"},
    {LIBLTE_MME_ESM_CAUSE_CONDITIONAL_IE_ERROR, "Conditional IE error"},
    {LIBLTE_MME_ESM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE,
     "message not compatible with the protocol stat"},
    {LIBLTE_MME_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
     "Protocol error, unspecified"},
    {LIBLTE_MME_ESM_CAUSE_APN_RESTRICTION_VALUE_INCOMPATIBLE_WITH_ACTIVE_EPS_BEARER_CONTEXT,
     "APN restriction value incompatible with active EPS bearer context"}};
void set_esm_cause(uint8 esm_cause, std::ostream &ostream,
                   const std::string &indent);

std::string set_hex_data(const uint8 *data, int size);

void set_auth_request(
    const LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT &auth_req,
    std::ostream &ostream, const std::string &indent);

void set_auth_response(
    const LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT &auth_response,
    std::ostream &ostream, const ::std::string &indent);

void set_auth_failure(
    const LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT &auth_failure,
    std::ostream &ostream, const std::string &indent);

void set_nas_sec_algs(
    const LIBLTE_MME_NAS_SECURITY_ALGORITHMS_STRUCT &nas_sec_algs,
    std::ostream &ostream, const std::string &indent);

void set_ue_security_capability(
    const LIBLTE_MME_UE_SECURITY_CAPABILITIES_STRUCT &ue_sec_cap,
    std::ostream &ostream, const std::string &indent);

void set_security_mode_command(
    const LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT &sec_mode_cmd,
    std::ostream &ostream, const std::string &indent);

void set_mobile_id(const LIBLTE_MME_MOBILE_ID_STRUCT &mobile_id,
                   std::ostream &ostream, const std::string &indent);

void set_security_mode_complete(
    const LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT &sec_mode_comp,
    std::ostream &ostream, const std::string &indent);

const static std::map<int, std::string> eps_attach_result_strings = {
    {1, "EPS only"}, {2, "combined EPS/IMSI attach"}};

void set_attach_result(uint8 eps_attach_result, std::ostream &ostream,
                       const std::string indent);

const static std::map<int, std::string> gprs_timer_unit_strings = {
    {LIBLTE_MME_GPRS_TIMER_UNIT_2_SECONDS, "2 seconds"},
    {LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE, "1 minute"},
    {LIBLTE_MME_GPRS_TIMER_UNIT_6_MINUTES, "6 minutes"},
    {LIBLTE_MME_GPRS_TIMER_DEACTIVATED, "Deactivated"}};

void set_gprs_timer(const LIBLTE_MME_GPRS_TIMER_STRUCT &gprs_timer,
                    const std::string timer_name, std::ostream &ostream,
                    const std::string &indent);

const static std::map<int, std::string> gprs_timer_3_unit_strings = {

    {LIBLTE_MME_GPRS_TIMER_3_UNIT_10_MINUTES, "10 minutes"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_1_HOUR, "1 hour"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_10_HOURS, "10 hours"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_2_SECONDS, "2 seconds"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_30_SECONDS, "30 seconds"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_1_MINUTE, "10 minutes"},
    {LIBLTE_MME_GPRS_TIMER_3_UNIT_320_HOURS, "320 hours"},
    {LIBLTE_MME_GPRS_TIMER_3_DEACTIVATED, "Deactivated"}};
void set_gprs_timer_3(const LIBLTE_MME_GPRS_TIMER_3_STRUCT &gprs_timer,
                      const std::string timer_name, std::ostream &ostream,
                      const std::string &indent);

void set_gprs_timer_2(uint8 value, const std::string timer_name,
                      std::ostream &stream, const std::string &indent);

void set_tracking_area_id(const LIBLTE_MME_TRACKING_AREA_ID_STRUCT &tai,
                          std::ostream &ostream, const std::string &indent);
void set_tracking_area_id_list(
    const LIBLTE_MME_TRACKING_AREA_IDENTITY_LIST_STRUCT &tai_list,
    std::ostream &ostream, const std::string indent);

void set_location_area_id(const LIBLTE_MME_LOCATION_AREA_ID_STRUCT &lai,
                          std::ostream &ostream, const std::string &indent);

void set_plmn_list(const LIBLTE_MME_PLMN_LIST_STRUCT &plmn_list,
                   const std::string plmn_name, std::ostream &ostream,
                   const std::string indent);

void set_emergency_number(const LIBLTE_MME_EMERGENCY_NUMBER_STRUCT &emerg_num,
                          std::ostream &ostream, const std::string &indent);
void set_emergency_number_list(
    const LIBLTE_MME_EMERGENCY_NUMBER_LIST_STRUCT &emerg_num_list,
    std::ostream &ostream, std::string indent);

void set_eps_network_feature_support(
    const LIBLTE_MME_EPS_NETWORK_FEATURE_SUPPORT_STRUCT &eps_nfs,
    std::ostream &ostream, const std::string indent);

void set_additional_update_result(
    LIBLTE_MME_ADDITIONAL_UPDATE_RESULT_ENUM update_result,
    std::ostream &ostream, const std::string &indent);

void set_extended_drx(const LIBLTE_MME_EXTENDED_DRX_STRUCT &eDrx,
                      std::ostream &ostream, const std::string &indent);

void set_eps_qos(const LIBLTE_MME_EPS_QUALITY_OF_SERVICE_STRUCT &eps_qos,
                 std::ostream &ostream, const std::string indent);

void set_pdn_address(const LIBLTE_MME_PDN_ADDRESS_STRUCT &pdn_addr,
                     std::ostream &ostream, const std::string indent);

void set_header_compression_configuration(
    const LIBLTE_MME_HEADER_COMPRESSION_CONFIGURATION_STRUCT
        &header_compress_cfg,
    std::ostream &ostream, const std::string &indent);

void set_control_plane_only_indication(
    const LIBLTE_MME_CONTROL_PLANE_ONLY_INDICATION_ENUM &cpoi,
    std::ostream &ostream, const std::string &indent);

#endif  // __LIBLTE_DESC__
