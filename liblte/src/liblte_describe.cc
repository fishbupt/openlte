#include <iomanip>
#include <iostream>
#include <sstream>
#include "liblte_describe.h"

std::string liblte_mme_msg_to_string(LIBLTE_BYTE_MSG_STRUCT &mme_msg) {
  std::stringstream ostream;
  int indent = indent_size;
  std::string indent_str = std::string(indent, ' ');
  uint8 pd;
  uint8 sec_hdr_type;
  uint8 msg_type;
  uint8 mac[4];
  uint8 seq_num;
  liblte_mme_parse_msg_header(&mme_msg, &pd, &sec_hdr_type, mac, &seq_num,
                              &msg_type);
  set_pd(pd, ostream, indent_str);
  set_sec_hdr_type(sec_hdr_type, ostream, indent_str);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    set_mac(mac, ostream, indent_str);
    set_seq_num(seq_num, ostream, indent_str);
  }
  set_msg_type(msg_type, ostream, indent_str);

  switch (msg_type) {
    case LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST: {
      LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req{};
      liblte_mme_unpack_attach_request_msg(&mme_msg, &attach_req);
      set_attach_type(attach_req.eps_attach_type, ostream, indent_str);
      set_nas_key_set_identifier(attach_req.nas_ksi, ostream, indent_str);
      set_eps_mobile_id(attach_req.eps_mobile_id, ostream, indent_str);
      set_ue_network_cap(attach_req.ue_network_cap, ostream, indent_str);
      set_esm_message_container(&attach_req.esm_msg, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT: {
      LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT attach_accept{};
      liblte_mme_unpack_attach_accept_msg(&mme_msg, &attach_accept);
      set_attach_result(attach_accept.eps_attach_result, ostream, indent_str);
      set_gprs_timer(attach_accept.t3412, "T3412", ostream, indent_str);
      set_tracking_area_id_list(attach_accept.tai_list, ostream, indent_str);
      set_esm_message_container(&attach_accept.esm_msg, ostream, indent_str);
      if (attach_accept.guti_present) {
        set_eps_mobile_id(attach_accept.guti, ostream, indent_str);
      }
      if (attach_accept.lai_present) {
        set_location_area_id(attach_accept.lai, ostream, indent_str);
      }
      if (attach_accept.ms_id_present) {
        set_mobile_id(attach_accept.ms_id, ostream, indent_str);
      }
      if (attach_accept.emm_cause_present) {
        set_emm_cause(attach_accept.emm_cause, ostream, indent_str);
      }
      if (attach_accept.t3402_present) {
        set_gprs_timer(attach_accept.t3402, "T3402", ostream, indent_str);
      }
      if (attach_accept.t3423_present) {
        set_gprs_timer(attach_accept.t3423, "T3423", ostream, indent_str);
      }
      if (attach_accept.equivalent_plmns_present) {
        set_plmn_list(attach_accept.equivalent_plmns, "Equivalent PLMNs",
                      ostream, indent_str);
      }
      if (attach_accept.emerg_num_list_present) {
        set_emergency_number_list(attach_accept.emerg_num_list, ostream,
                                  indent_str);
      }
      if (attach_accept.eps_network_feature_support_present) {
        set_eps_network_feature_support(
            attach_accept.eps_network_feature_support, ostream, indent_str);
      }
      if (attach_accept.additional_update_result_present) {
        set_additional_update_result(attach_accept.additional_update_result,
                                     ostream, indent_str);
      }
      if (attach_accept.t3412_ext_present) {
        set_gprs_timer_3(attach_accept.t3412_ext, "T3412 extended", ostream,
                         indent_str);
      }
      if (attach_accept.eDrx_param_present) {
        set_extended_drx(attach_accept.eDrx_param, ostream, indent_str);
      }
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE: {
      LIBLTE_MME_ATTACH_COMPLETE_MSG_STRUCT attach_comp{};
      liblte_mme_unpack_attach_complete_msg(&mme_msg, &attach_comp);
      set_esm_message_container(&attach_comp.esm_msg, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_REJECT: {
      LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_rej{};
      liblte_mme_unpack_attach_reject_msg(&mme_msg, &attach_rej);
      set_emm_cause(attach_rej.emm_cause, ostream, indent_str);
      if (attach_rej.esm_msg_present) {
        set_esm_message_container(&attach_rej.esm_msg, ostream, indent_str);
      }
      break;
    }
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
    case LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST: {
      break;
    }
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
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST: {
      LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req{};
      liblte_mme_unpack_authentication_request_msg(&mme_msg, &auth_req);
      set_nas_key_set_identifier(auth_req.nas_ksi, ostream, indent_str);
      set_auth_request(auth_req, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE: {
      LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT auth_response{};
      liblte_mme_unpack_authentication_response_msg(&mme_msg, &auth_response);
      set_auth_response(auth_response, ostream, indent_str);
    }
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT:  // No special handler for
                                                     // this message
      break;
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE: {
      LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT auth_failure{};
      liblte_mme_unpack_authentication_failure_msg(&mme_msg, &auth_failure);
      set_auth_failure(auth_failure, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST:
      break;
    case LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE:
      break;
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND: {
      LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sec_mode_cmd{};
      liblte_mme_unpack_security_mode_command_msg(&mme_msg, &sec_mode_cmd);
      set_security_mode_command(sec_mode_cmd, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE: {
      LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT sec_mode_comp{};
      liblte_mme_unpack_security_mode_complete_msg(&mme_msg, &sec_mode_comp);
      set_security_mode_complete(sec_mode_comp, ostream, indent_str);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT: {
      LIBLTE_MME_SECURITY_MODE_REJECT_MSG_STRUCT sec_mode_rej{};
      liblte_mme_unpack_security_mode_reject_msg(&mme_msg, &sec_mode_rej);
      set_emm_cause(sec_mode_rej.emm_cause, ostream, indent_str);
      break;
    }
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
                               std::ostream &ostream,
                               const std::string &indent) {
  uint8 pd;
  uint8 sec_hdr_type;
  uint8 msg_type;
  uint8 mac[4];
  uint8 seq_num;
  liblte_mme_parse_msg_header(esm_msg, &pd, &sec_hdr_type, mac, &seq_num,
                              &msg_type);
  ostream << std::string(indent, ' ') << "ESM message container: " << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  set_pd(pd, ostream, indent_str);

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
      set_eps_bearer_id(pdn_con_req.eps_bearer_id, ostream, indent_str);
      set_proc_transaction_id(pdn_con_req.proc_transaction_id, ostream,
                              indent_str);
      set_pdn_connectivity_request(pdn_con_req, ostream, indent_str);
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
void set_pd(uint8 eps_pd, std::ostream &ostream, const std::string &indent) {
  std::string desc;
  auto it = pd_strings.find(eps_pd);
  if (it == pd_strings.end()) {
    desc = "Unknown Protocol discriminator";
  } else {
    desc = pd_strings.at(eps_pd);
  }
  ostream << indent << "Protocol discriminator = 0x" << hex_out_s(eps_pd)
          << " (" << desc << ")" << std::endl;
}

void set_sec_hdr_type(uint8 sec_hdr_type, std::ostream &ostream,
                      const std::string &indent) {
  std::string desc;
  auto it = securiy_header_type_strings.find(sec_hdr_type);
  if (it == securiy_header_type_strings.end()) {
    desc = "Unknown Security Header Type";
  } else {
    desc = securiy_header_type_strings.at(sec_hdr_type);
  }
  ostream << indent << "Securiy header = 0x" << hex_out_s(sec_hdr_type) << " ("
          << desc << ")" << std::endl;
}

void set_msg_type(uint8 msg_type, std::ostream &ostream,
                  const std::string &indent) {
  std::string desc;
  auto it = message_type_strings.find(msg_type);
  if (it == message_type_strings.end()) {
    desc = "Unknown Message type";
  } else {
    desc = message_type_strings.at(msg_type);
  }
  ostream << indent << "Message type = 0x" << hex_out_s(msg_type) << " ("
          << desc << ")" << std::endl;
}

void set_emm_cause(uint8 emm_cause, std::ostream &ostream,
                   const std::string &indent) {
  std::string desc;
  auto it = emm_cause_strings.find(emm_cause);
  if (it == emm_cause_strings.end()) {
    desc = "Unknown EMM Cause";
  } else {
    desc = emm_cause_strings.at(emm_cause);
  }
  ostream << indent << "EMM cause = 0x" << hex_out_s(emm_cause) << " (" << desc
          << ")" << std::endl;
}

void set_mac(uint8 *mac, std::ostream &ostream, const std::string &indent) {
  ostream << indent << "MAC = 0x" << hex_out_s(mac[0]) << hex_out_s(mac[1])
          << hex_out_s(mac[2]) << hex_out_s(mac[3]) << std::endl;
}

void set_seq_num(uint8 seq_num, std::ostream &ostream,
                 const std::string &indent) {
  ostream << indent << "Sequence number = 0x" << hex_out_s(seq_num)
          << std::endl;
}

// EPS bearer id
void set_eps_bearer_id(uint8 eps_bearer_id, std::ostream &ostream,
                       const std::string &indent) {
  ostream << indent << "EPS bearer identity = " << +eps_bearer_id << std::endl;
}

// Procedure transaction id
void set_proc_transaction_id(uint8 proc_transaction_id, std::ostream &ostream,
                             const std::string &indent) {
  ostream << indent
          << "Procedure transaction identity = " << +proc_transaction_id
          << std::endl;
}

void set_attach_type(uint8 attach_type, std::ostream &ostream,
                     const std::string &indent) {
  std::string desc;
  auto it = attach_type_strings.find(attach_type);
  if (it == attach_type_strings.end()) {
    desc = "Unknown Attach type";
  } else {
    desc = attach_type_strings.at(attach_type);
  }

  ostream << indent << "EPS attach type = " << +attach_type << " (" << desc
          << ")" << std::endl;
}

// NAS key set identifier
void set_nas_key_set_identifier(const LIBLTE_MME_NAS_KEY_SET_ID_STRUCT &nas_ksi,
                                std::ostream &ostream,
                                const std::string &indent) {
  ostream << indent << "NAS key set identifier:" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << std::string(indent_str, ' ') << "TSC = " << nas_ksi.tsc_flag
          << std::endl;
  ostream << std::string(indent_str, ' ')
          << "NAS key set identifier = " << +nas_ksi.nas_ksi << std::endl;
}

// EPS mobile identity
void set_eps_mobile_id(const LIBLTE_MME_EPS_MOBILE_ID_STRUCT &eps_mobile_id,
                       std::ostream &ostream, const std::string &indent) {
  ostream << indent << "Old GUTI or IMSI" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  switch (eps_mobile_id.type_of_id) {
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI:
      set_guti(eps_mobile_id.guti, ostream, indent_str);
      break;
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI:
      set_imei(eps_mobile_id.imei, ostream, indent_str);
      break;
    case LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI:
      set_imsi(eps_mobile_id.imsi, ostream, indent_str);
      break;
  }
}

void set_guti(const LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT &guti,
              std::ostream &ostream, const std::string &indent) {
  ostream << indent << "GUTI:" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << indent_str << "MCC = " << guti.mcc << std::endl;
  ostream << indent_str << "MNC = " << guti.mnc << std::endl;
  ostream << indent_str << "MME Group Id = " << guti.mme_group_id << std::endl;
  ostream << indent_str << "MME Code = " << +guti.mme_code << std::endl;
  ostream << indent_str << "M-TMSI = " << guti.m_tmsi << std::endl;
}

void set_imsi(const uint8 *imsi, std::ostream &ostream,
              const std::string &indent) {
  ostream << indent << "IMSI = ";
  for (int i = 0; i < 15; i++) {
    ostream << +imsi[i];  // implicit convert to int
  }
  ostream << std::endl;
}

void set_imei(const uint8 *imei, std::ostream &ostream,
              const std::string &indent) {
  ostream << indent << "IMEI = ";
  for (int i = 0; i < 15; i++) {
    ostream << +imei[i];
  }
  ostream << std::endl;
}

void set_imeisv(const uint8 *imeisv, std::ostream &ostream,
                const std::string &indent) {
  ostream << indent << "IMEISV = ";
  for (int i = 0; i < 16; i++) {
    ostream << +imeisv[i];
  }
  ostream << std::endl;
}

void set_tmgi(const LIBLTE_MME_MOBILE_ID_TMGI_STRUCT &tmgi,
              std::ostream &ostream, const std::string &indent) {
  ostream << indent << "TMGI:" << std::endl;

  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << "MBMS Service ID = " << tmgi.mbms_service_id << std::endl;
  if (tmgi.mcc_mnc_ind) {
    ostream << indent_str << "MCC = " << tmgi.mcc << std::endl;
    ostream << indent_str << "MNC = " << tmgi.mnc << std::endl;
  }
  if (tmgi.mbms_session_id_ind) {
    ostream << "MBMS Session Identity = " << +tmgi.mbms_session_id << std::endl;
  }
}

// UE network capability
void set_ue_network_cap(
    const LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT &ue_network_cap,
    std::ostream &ostream, const std::string &indent) {
  ostream << indent << "UE network capability: " << std::endl;
  auto indent_str = std::string(indent_size, ' ') + indent;

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
    std::ostream &ostream, const std::string &indent) {
  ostream << indent << "Request type = " << +pdn_con_req.request_type
          << std::endl;

  std::string pdn_type_desc;
  auto it = pdn_type_strings.find(pdn_con_req.pdn_type);
  if (it == pdn_type_strings.end()) {
    pdn_type_desc = "Unknown PDN type";
  } else {
    pdn_type_desc = pdn_type_strings.at(pdn_con_req.pdn_type);
  }
  ostream << indent << "PDN type = " << +pdn_con_req.pdn_type << " ("
          << pdn_type_desc << ")" << std::endl;
}

std::string set_hex_data(const uint8 *data, int size) {
  std::stringstream ss;
  for (int i = 0; i < size; i++) {
    ss << hex_out_s(data[i]) << " ";
  }
  return ss.str();
}

void set_auth_request(
    const LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT &auth_req,
    std::ostream &ostream, const std::string &indent) {
  std::string indent_str = indent + std::string(indent_size, ' ');

  ostream << indent << "Authenication parameter RAND: " << std::endl;
  ostream << indent_str << "Data = " << set_hex_data(auth_req.rand, 16)
          << std::endl;

  ostream << indent << "Authenication parameter AUTN: " << std::endl;
  ostream << indent_str << "Data = " << set_hex_data(auth_req.autn, 16)
          << std::endl;
}

void set_auth_response(
    const LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT &auth_response,
    std::ostream &ostream, const ::std::string &indent) {
  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << indent << "Authenication response parameter: " << std::endl;
  ostream << indent_str << "Data = " << set_hex_data(auth_response.res, 8)
          << std::endl;
}

void set_auth_failure(
    const LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT &auth_failure,
    std::ostream &ostream, const std::string &indent) {
  std::string indent_str = indent + std::string(indent_size, ' ');

  set_emm_cause(auth_failure.emm_cause, ostream, indent);
  if (auth_failure.auth_fail_param_present) {
    ostream << indent << "Authenication failure parameter: " << std::endl;
    ostream << indent_str
            << "Data = " << set_hex_data(auth_failure.auth_fail_param, 14)
            << std::endl;
  }
}

void set_nas_sec_algs(
    const LIBLTE_MME_NAS_SECURITY_ALGORITHMS_STRUCT &nas_sec_algs,
    std::ostream &ostream, const std::string &indent) {
  ostream << indent << "Selected NAS security algorithms:" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');

  ostream
      << indent_str << "Type of ciphering algorithm = "
      << liblte_mme_type_of_ciphering_algorithm_text[nas_sec_algs.type_of_eea]
      << std::endl;
  ostream
      << indent_str << "Type of integrity protection algorithm = "
      << liblte_mme_type_of_integrity_algorithm_text[nas_sec_algs.type_of_eia]
      << std::endl;
}

void set_ue_security_capability(
    const LIBLTE_MME_UE_SECURITY_CAPABILITIES_STRUCT &ue_sec_cap,
    std::ostream &ostream, const std::string &indent) {
  ostream << "Replayed UE security capabilities: " << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');

  ostream << indent_str << "EEA = [";
  ostream << ue_sec_cap.eea[0];
  for (int i = 1; i < 8; i++) {
    ostream << "," << ue_sec_cap.eea[i];
  }
  ostream << "]" << std::endl;

  ostream << indent_str << "EIA = [";
  ostream << ue_sec_cap.eia[0];
  for (int i = 1; i < 8; i++) {
    ostream << "," << ue_sec_cap.eia[i];
  }
  ostream << "]" << std::endl;

  if (ue_sec_cap.uea_present) {
    ostream << indent_str << "UEA = [";
    ostream << ue_sec_cap.uea[0];
    for (int i = 1; i < 8; i++) {
      ostream << "," << ue_sec_cap.uea[i];
    }
    ostream << "]" << std::endl;
  }
  if (ue_sec_cap.uia_present) {
    ostream << indent_str << "UIA = [";
    ostream << ue_sec_cap.uia[0];
    for (int i = 1; i < 8; i++) {
      ostream << "," << ue_sec_cap.uia[i];
    }
    ostream << "]" << std::endl;
  }
  if (ue_sec_cap.gea_present) {
    ostream << indent_str << "GEA = [";
    ostream << ue_sec_cap.gea[0];
    for (int i = 1; i < 8; i++) {
      ostream << "," << ue_sec_cap.gea[i];
    }
    ostream << "]" << std::endl;
  }
}

void set_security_mode_command(
    const LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT &sec_mode_cmd,
    std::ostream &ostream, const std::string &indent) {
  set_nas_sec_algs(sec_mode_cmd.selected_nas_sec_algs, ostream, indent);
  set_nas_key_set_identifier(sec_mode_cmd.nas_ksi, ostream, indent);
  set_ue_security_capability(sec_mode_cmd.ue_security_cap, ostream, indent);

  if (sec_mode_cmd.imeisv_req_present) {
    ostream << "IMEISV request = "
            << liblte_mme_imeisv_request_text[sec_mode_cmd.imeisv_req]
            << std::endl;
  }
  if (sec_mode_cmd.nonce_ue_present) {
    ostream << "Replayed nonce UE = " << sec_mode_cmd.nonce_ue << std::endl;
  }
  if (sec_mode_cmd.nonce_mme_present) {
    ostream << "Nonce MME = " << sec_mode_cmd.nonce_mme << std::endl;
  }
}

void set_mobile_id(const LIBLTE_MME_MOBILE_ID_STRUCT &mobile_id,
                   std::ostream &ostream, const std::string &indent) {
  switch (mobile_id.type_of_id) {
    case LIBLTE_MME_MOBILE_ID_TYPE_IMSI:
      set_imsi(mobile_id.imsi, ostream, indent);
      break;
    case LIBLTE_MME_MOBILE_ID_TYPE_IMEI:
      set_imei(mobile_id.imei, ostream, indent);
      break;
    case LIBLTE_MME_MOBILE_ID_TYPE_IMEISV:
      break;
    case LIBLTE_MME_MOBILE_ID_TYPE_TMGI:
      break;
  }
}

void set_security_mode_complete(
    const LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT &sec_mode_comp,
    std::ostream &ostream, const std::string &indent) {
  if (sec_mode_comp.imeisv_present) {
    ostream << indent << "IMEISV: " << std::endl;
    std::string indent_str = indent + std::string(indent_size, ' ');
    set_mobile_id(sec_mode_comp.imeisv, ostream, indent_str);
  }
}

void set_attach_result(uint8 eps_attach_result, std::ostream &ostream,
                       const std::string indent) {
  std::string desc;
  auto it = eps_attach_result_strings.find(eps_attach_result);
  if (it == eps_attach_result_strings.end()) {
    desc = "Unknown EPS Attach result";
  } else {
    desc = eps_attach_result_strings.at(eps_attach_result);
  }
  ostream << indent << "EPS Attach result = " << +eps_attach_result << "( "
          << desc << ")" << std::endl;
}
void set_gprs_timer(const LIBLTE_MME_GPRS_TIMER_STRUCT &gprs_timer,
                    const std::string timer_name, std::ostream &ostream,
                    const std::string &indent) {
  ostream << indent << timer_name << ":" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  std::string desc;
  auto it = gprs_timer_unit_strings.find(gprs_timer.unit);
  if (it == gprs_timer_unit_strings.end()) {
    desc = "Unknown Timer Unit";
  } else {
    desc = gprs_timer_unit_strings.at(gprs_timer.unit);
  }
  ostream << indent_str << "value = " << +gprs_timer.value << std::endl;
  ostream << indent_str << "unit = " << +gprs_timer.unit << " (" << desc << ")"
          << std::endl;
}
void set_gprs_timer_3(const LIBLTE_MME_GPRS_TIMER_3_STRUCT &gprs_timer,
                      const std::string timer_name, std::ostream &ostream,
                      const std::string &indent) {
  ostream << indent << timer_name << ":" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  std::string desc;
  auto it = gprs_timer_3_unit_strings.find(gprs_timer.unit);
  if (it == gprs_timer_3_unit_strings.end()) {
    desc = "Unknown Timer Unit";
  } else {
    desc = gprs_timer_3_unit_strings.at(gprs_timer.unit);
  }
  ostream << indent_str << "value = " << +gprs_timer.value << std::endl;
  ostream << indent_str << "unit = " << +gprs_timer.unit << " (" << desc << ")"
          << std::endl;
}

void set_tracking_area_id(const LIBLTE_MME_TRACKING_AREA_ID_STRUCT &tai,
                          std::ostream &ostream, const std::string &indent) {
  ostream << indent << "MCC = " << tai.mcc << std::endl;
  ostream << indent << "MNC = " << tai.mnc << std::endl;
  ostream << indent << "TAC = " << tai.tac << std::endl;
}

void set_tracking_area_id_list(
    const LIBLTE_MME_TRACKING_AREA_IDENTITY_LIST_STRUCT &tai_list,
    std::ostream &ostream, const std::string indent) {
  ostream << indent << "TAI list: " << std::endl;
  auto indent_str = indent + std::string(indent_size, ' ');
  for (int i = 0; i < tai_list.N_tais; i++) {
    set_tracking_area_id(tai_list.tai[i], ostream, indent_str);
  }
}

void set_location_area_id(const LIBLTE_MME_LOCATION_AREA_ID_STRUCT &lai,
                          std::ostream &ostream, const std::string &indent) {
  ostream << indent << "MCC = " << lai.mcc << std::endl;
  ostream << indent << "MNC = " << lai.mnc << std::endl;
  ostream << indent << "LAC = " << lai.lac << std::endl;
}

void set_plmn_list(const LIBLTE_MME_PLMN_LIST_STRUCT &plmn_list,
                   const std::string plmn_name, std::ostream &ostream,
                   const std::string indent) {
  ostream << indent << plmn_name << ":" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');

  for (int i = 0; i < plmn_list.N_plmns; i++) {
    ostream << indent_str << "MCC = " << plmn_list.mcc[i] << std::endl;
    ostream << indent_str << "MNC = " << plmn_list.mnc[i] << std::endl;
  }
}
void set_emergency_number(const LIBLTE_MME_EMERGENCY_NUMBER_STRUCT &emerg_num,
                          std::ostream &ostream, const std::string &indent) {
  ostream
      << indent << "Emergency Serice Category = " << emerg_num.emerg_service_cat
      << " ("
      << liblte_mme_emergency_service_category_text[emerg_num.emerg_service_cat]
      << ")" << std::endl;
  ostream << indent << "Number = ";
  for (int i = 0; i < emerg_num.N_emerg_num_digits; i++) {
    ostream << +emerg_num.emerg_num[i];
  }
  ostream << std::endl;
}
void set_emergency_number_list(
    const LIBLTE_MME_EMERGENCY_NUMBER_LIST_STRUCT &emerg_num_list,
    std::ostream &ostream, std::string indent) {
  ostream << indent << "Emergency Number List:" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  for (int i = 0; i < emerg_num_list.N_emerg_nums; i++) {
    set_emergency_number(emerg_num_list.emerg_num[i], ostream, indent_str);
  }
}

void set_eps_network_feature_support(
    const LIBLTE_MME_EPS_NETWORK_FEATURE_SUPPORT_STRUCT &eps_nfs,
    std::ostream &ostream, const std::string indent) {
  ostream << "EPS network feature support:" << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << indent_str << "CP CIoT = " << eps_nfs.cp_ciot << std::endl;
  ostream << indent_str << "ERw/o PDN = " << eps_nfs.erwo_pdn << std::endl;
  ostream << indent_str << "ESR PS = " << eps_nfs.esrps << std::endl;
  ostream << indent_str << "CS-LCS = " << eps_nfs.cs_lcs << std::endl;
  ostream << indent_str << "EPC-LCS = " << eps_nfs.epc_lcs << std::endl;
  ostream << indent_str << "EMC BS = " << eps_nfs.emc_bs << std::endl;
  ostream << indent_str << "IMS VoPS = " << eps_nfs.ims_vops << std::endl;
  ostream << indent_str << "HC-CP CIoT = " << eps_nfs.hc_cp_ciot << std::endl;
  ostream << indent_str << "S1-U data = " << eps_nfs.s1_u << std::endl;
  ostream << indent_str << "UP CIoT = " << eps_nfs.up_ciot << std::endl;
}

void set_additional_update_result(
    LIBLTE_MME_ADDITIONAL_UPDATE_RESULT_ENUM update_result,
    std::ostream &ostream, const std::string &indent) {
  ostream << indent << "Additional update result = " << update_result << " ("
          << liblte_mme_additional_update_result_text[update_result] << ")"
          << std::endl;
}

void set_extended_drx(const LIBLTE_MME_EXTENDED_DRX_STRUCT &eDrx,
                      std::ostream &ostream, const std::string &indent) {
  ostream << "Extended DRX Parameter: " << std::endl;
  std::string indent_str = indent + std::string(indent_size, ' ');
  ostream << indent_str << "Paging Time Window = " << eDrx.paging_time_window
          << std::endl;
  ostream << indent_str << "eDRX value = " << eDrx.eDRX_value << std::endl;
}
