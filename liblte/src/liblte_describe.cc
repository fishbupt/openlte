#include <iomanip>
#include <iostream>
#include <sstream>
#include "liblte_describe.h"

std::string liblte_mme_msg_to_string(LIBLTE_BYTE_MSG_STRUCT &mme_msg) {
  std::stringstream ostream;
  int indent = indent_size;
  uint8 pd;
  uint8 sec_hdr_type;
  uint8 msg_type;
  uint8 mac[4];
  uint8 seq_num;
  liblte_mme_parse_msg_header(&mme_msg, &pd, &sec_hdr_type, mac, &seq_num,
                              &msg_type);
  set_pd(pd, ostream, indent);
  set_sec_hdr_type(sec_hdr_type, ostream, indent);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    set_mac(mac, ostream, indent);
    set_seq_num(seq_num, ostream, indent);
  }
  set_msg_type(msg_type, ostream, indent);

  switch (msg_type) {
    case LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST: {
      LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req;
      liblte_mme_unpack_attach_request_msg(&mme_msg, &attach_req);
      set_attach_type(attach_req.eps_attach_type, ostream, indent);
      set_nas_key_set_identifier(attach_req.nas_ksi, ostream, indent);
      set_eps_mobile_id(attach_req.eps_mobile_id, ostream, indent);
      set_ue_network_cap(attach_req.ue_network_cap, ostream, indent);
      set_esm_message_container(&attach_req.esm_msg, ostream, indent);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE:
      break;
    case LIBLTE_MME_MSG_TYPE_ATTACH_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_DETACH_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_COMPLETE:
      break;
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_CONTROL_PLANE_SERVICE_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_SERVICE_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_SERVICE_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND:
      break;
    case LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMPLETE:
      break;
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE:
      break;
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE:
      break;
    case LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE:
      break;
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND:
      break;
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE:
      break;
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_EMM_STATUS:
      break;
    case LIBLTE_MME_MSG_TYPE_EMM_INFORMATION:
      break;
    case LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT:
      break;
    case LIBLTE_MME_MSG_TYPE_UPLINK_NAS_TRANSPORT:
      break;
    case LIBLTE_MME_MSG_TYPE_CS_SERVICE_NOTIFICATION:
      break;
    case LIBLTE_MME_MSG_TYPE_DOWNLINK_GENERIC_NAS_TRANSPORT:
      break;
    case LIBLTE_MME_MSG_TYPE_UPLINK_GENERIC_NAS_TRANSPORT:
      break;
  }

  return ostream.str();
}

void set_esm_message_container(LIBLTE_BYTE_MSG_STRUCT *esm_msg,
                               std::ostream &ostream, int indent) {
  uint8 pd;
  uint8 sec_hdr_type;
  uint8 msg_type;
  uint8 mac[4];
  uint8 seq_num;
  liblte_mme_parse_msg_header(esm_msg, &pd, &sec_hdr_type, mac, &seq_num,
                              &msg_type);
  ostream << std::string(indent, ' ') << "ESM message container: " << std::endl;
  indent += indent_size;
  set_pd(pd, ostream, indent);

  switch (msg_type) {
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT:
      break;
    case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST: {
      LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_con_req;
      liblte_mme_unpack_pdn_connectivity_request_msg(esm_msg, &pdn_con_req);
      set_eps_bearer_id(pdn_con_req.eps_bearer_id, ostream, indent);
      set_proc_transaction_id(pdn_con_req.proc_transaction_id, ostream, indent);
      set_pdn_connectivity_request(pdn_con_req, ostream, indent);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT:
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE:
      break;
    case LIBLTE_MME_MSG_TYPE_NOTIFICATION:
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_STATUS:
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_DATA_TRANSPORT:
      break;
  }
}
void set_pd(uint8 eps_pd, std::ostream &ostream, int indent) {
  std::string desc;
  auto it = pd_strings.find(eps_pd);
  if (it == pd_strings.end()) {
    desc = "Unknown Protocol discriminator";
  } else {
    desc = pd_strings.at(eps_pd);
  }
  ostream << std::string(indent, ' ') << "Protocol discriminator = 0x"
          << hex_out_s(eps_pd) << " (" << desc << ")" << std::endl;
}

void set_sec_hdr_type(uint8 sec_hdr_type, std::ostream &ostream, int indent) {
  std::string desc;
  auto it = securiy_header_type_strings.find(sec_hdr_type);
  if (it == securiy_header_type_strings.end()) {
    desc = "Unknown Security Header Type";
  } else {
    desc = securiy_header_type_strings.at(sec_hdr_type);
  }
  ostream << std::string(indent, ' ') << "Securiy header = 0x"
          << hex_out_s(sec_hdr_type) << " (" << desc << ")" << std::endl;
}

void set_msg_type(uint8 msg_type, std::ostream &ostream, int indent) {
  std::string desc;
  auto it = message_type_strings.find(msg_type);
  if (it == message_type_strings.end()) {
    desc = "Unknown Message type";
  } else {
    desc = message_type_strings.at(msg_type);
  }
  ostream << std::string(indent, ' ') << "Message type = 0x"
          << hex_out_s(msg_type) << " (" << desc << ")" << std::endl;
}

void set_mac(uint8 *mac, std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "MAC = 0x" << hex_out_s(mac[0])
          << hex_out_s(mac[1]) << hex_out_s(mac[2]) << hex_out_s(mac[3])
          << std::endl;
}

void set_seq_num(uint8 seq_num, std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "Sequence number = 0x"
          << hex_out_s(seq_num) << std::endl;
}

// EPS bearer id
void set_eps_bearer_id(uint8 eps_bearer_id, std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ')
          << "EPS bearer identity = " << +eps_bearer_id << std::endl;
}

// Procedure transaction id
void set_proc_transaction_id(uint8 proc_transaction_id, std::ostream &ostream,
                             int indent) {
  ostream << std::string(indent, ' ')
          << "Procedure transaction identity = " << +proc_transaction_id
          << std::endl;
}

void set_attach_type(uint8 attach_type, std::ostream &ostream, int indent) {
  std::string desc;
  auto it = attach_type_strings.find(attach_type);
  if (it == attach_type_strings.end()) {
    desc = "Unknown Attach type";
  } else {
    desc = attach_type_strings.at(attach_type);
  }

  ostream << std::string(indent, ' ') << "EPS attach type = " << +attach_type
          << " (" << desc << ")" << std::endl;
}

// NAS key set identifier
void set_nas_key_set_identifier(const LIBLTE_MME_NAS_KEY_SET_ID_STRUCT &nas_ksi,
                                std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "NAS key set identifier:" << std::endl;
  indent += indent_size;
  ostream << std::string(indent, ' ') << "TSC = " << nas_ksi.tsc_flag
          << std::endl;
  ostream << std::string(indent, ' ')
          << "NAS key set identifier = " << +nas_ksi.nas_ksi << std::endl;
}

// EPS mobile identity
void set_eps_mobile_id(const LIBLTE_MME_EPS_MOBILE_ID_STRUCT &eps_mobile_id,
                       std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "Old GUTI or IMSI" << std::endl;
  indent += indent_size;
  switch (eps_mobile_id.type_of_id) {
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI:
      set_guti(eps_mobile_id.guti, ostream, indent);
      break;
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI:
      set_imei(eps_mobile_id.imei, ostream, indent);
      break;
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI:
      set_imsi(eps_mobile_id.imsi, ostream, indent);
      break;
  }
}

void set_guti(const LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT &guti,
              std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "GUTI:" << std::endl;
  indent += indent_size;
  ostream << std::string(indent, ' ') << "MCC = " << guti.mcc << std::endl;
  ostream << std::string(indent, ' ') << "MNC = " << guti.mnc << std::endl;
  ostream << std::string(indent, ' ') << "MME Group Id = " << guti.mme_group_id
          << std::endl;
  ostream << std::string(indent, ' ') << "MME Code = " << +guti.mme_code
          << std::endl;
  ostream << std::string(indent, ' ') << "M-TMSI = " << guti.m_tmsi
          << std::endl;
}

void set_imsi(const uint8 *imsi, std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "IMSI = ";
  for (int i = 0; i < 15; i++) {
    ostream << +imsi[i];  // implicit convert to int
  }
  ostream << std::endl;
}

void set_imei(const uint8 *imei, std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "IMEI = ";
  for (int i = 0; i < 15; i++) {
    ostream << +imei[i];
  }
  ostream << std::endl;
}

// UE network capability
void set_ue_network_cap(
    const LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT &ue_network_cap,
    std::ostream &ostream, int indent) {
  ostream << std::string(indent, ' ') << "UE network capability: " << std::endl;
  indent += indent_size;
  auto indent_str = std::string(indent, ' ');

  ostream << indent_str << "EEA = [";
  ostream << ue_network_cap.eea[0];
  for (int i = 1; i < 8; i++) {
    ostream << "," << ue_network_cap.eea[i];
  }
  ostream << "]" << std::endl;

  ostream << indent_str << "EIA = [";
  ostream << ue_network_cap.eia[0];
  for (int i = 1; i < 8; i++) {
    ostream << "," << ue_network_cap.eia[i];
  }
  ostream << "]" << std::endl;

  if (ue_network_cap.uea_present) {
    ostream << indent_str << "UEA = [";
    ostream << ue_network_cap.uea[0];
    for (int i = 1; i < 8; i++) {
      ostream << "," << ue_network_cap.uea[i];
    }
    ostream << "]" << std::endl;
  }
  if (ue_network_cap.ucs2_present) {
    ostream << indent_str << "UCSE = " << ue_network_cap.ucs2 << std::endl;
  }

  if (ue_network_cap.uia_present) {
    ostream << indent_str << "UIA = [";
    ostream << ue_network_cap.uia[1];
    for (int i = 2; i < 8; i++) {
      ostream << "," << ue_network_cap.uia[i];
    }
    ostream << "]" << std::endl;
  }
  if (ue_network_cap.lpp_present) {
    ostream << indent_str << "LPP = " << ue_network_cap.lpp << std::endl;
  }
  if (ue_network_cap.lcs_present) {
    ostream << indent_str << "LCS = " << ue_network_cap.lcs << std::endl;
  }
  if (ue_network_cap.onexsrvcc_present) {
    ostream << indent_str << "1xSRVCC = " << ue_network_cap.onexsrvcc
            << std::endl;
  }
  if (ue_network_cap.nf_present) {
    ostream << indent_str << "NF = " << ue_network_cap.nf << std::endl;
  }
  if (ue_network_cap.ciot_present) {
    ostream << indent_str << "HP-CP CIoT = " << ue_network_cap.hc_cp_ciot
            << std::endl;
    ostream << indent_str << "ERw/o PDN = " << ue_network_cap.erwo_pdn
            << std::endl;
    ostream << indent_str << "S1-U data = " << ue_network_cap.s1_u << std::endl;
    ostream << indent_str << "UP CIoT = " << ue_network_cap.up_ciot
            << std::endl;
    ostream << indent_str << "CP CIoT = " << ue_network_cap.cp_ciot
            << std::endl;
    ostream << indent_str << "multiple eDRB = " << ue_network_cap.multiple_drb
            << std::endl;
  }
}

void set_pdn_connectivity_request(
    const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT &pdn_con_req,
    std::ostream &ostream, int indent) {
  auto indent_str = std::string(indent, ' ');
  ostream << indent_str << "Request type = " << +pdn_con_req.request_type
          << std::endl;

  std::string pdn_type_desc;
  auto it = pdn_type_strings.find(pdn_con_req.pdn_type);
  if (it == pdn_type_strings.end()) {
    pdn_type_desc = "Unknown PDN type";
  } else {
    pdn_type_desc = pdn_type_strings.at(pdn_con_req.pdn_type);
  }
  ostream << indent_str << "PDN type = " << +pdn_con_req.pdn_type << " ("
          << pdn_type_desc << ")" << std::endl;
}
