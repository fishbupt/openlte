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

void set_pd(uint8 eps_pd, std::ostream &ostream, int indent);

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

void set_sec_hdr_type(uint8 sec_hdr_type, std::ostream &ostream, int indent);

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

void set_msg_type(uint8 msg_type, std::ostream &ostream, int indent);

// Message Auth code
void set_mac(uint8 *mac, std::ostream &ostream, int indent);

// Sequence number
void set_seq_num(uint8 seq_num, std::ostream &ostream, int indent);

// EPS bearer id
void set_eps_bearer_id(uint8 eps_bearer_id, std::ostream &ostream, int indent);

// Procedure transaction id
void set_proc_transaction_id(uint8 proc_transaction_id, std::ostream &ostream,
                             int indent);
// Attach type
static const std::map<int, std::string> attach_type_strings{
    {1, "EPS attach"},
    {2, "combined EPS/IMSI attach"},
    {6, "EPS emergency attach"}};

// EPS attach type
void set_attach_type(uint8 attach_type, std::ostream &ostream, int indent);

// NAS key set identifier
void set_nas_key_set_identifier(const LIBLTE_MME_NAS_KEY_SET_ID_STRUCT &nas_ksi,
                                std::ostream &ostream, int indent);

void set_guti(const LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT &guti,
              std::ostream &ostream, int indent);

void set_imsi(const uint8 *imsi, std::ostream &ostream, int indent);

void set_imei(const uint8 *imei, std::ostream &ostream, int indent);

// EPS mobile identity
void set_eps_mobile_id(const LIBLTE_MME_EPS_MOBILE_ID_STRUCT &eps_mobile_id,
                       std::ostream &ostream, int indent);

// UE network capability
void set_ue_network_cap(
    const LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT &ue_network_cap,
    std::ostream &ostream, int indent);

// ESM message container
void set_esm_message_container(LIBLTE_BYTE_MSG_STRUCT *esm_msg,
                               std::ostream &ostream, int indent);

// PDN Connectivity Request
static const std::map<int, std::string> pdn_type_strings = {
    {LIBLTE_MME_PDN_TYPE_IPV4, "IPv4"},
    {LIBLTE_MME_PDN_TYPE_IPV6, "IPv6"},
    {LIBLTE_MME_PDN_TYPE_UNUSED, "unused"},
    {LIBLTE_MME_PDN_TYPE_NONIP, "non IP"}};

void set_pdn_connectivity_request(
    const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT &pdn_con_req,
    std::ostream &ostream, int indent);
#endif  // __LIBLTE_DESC__
