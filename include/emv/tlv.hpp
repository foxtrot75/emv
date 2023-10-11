#pragma once

#include <vector>
#include <map>

#include <loguru.hpp>

#include <tools/bytes.hpp>

namespace
{

std::string tagDescription(uint32_t tag) {
    switch(tag)
    {
        case 0x00000042: return "Issuer Identification Number (IIN)";
        case 0x0000004f: return "Application Dedicated File (ADF) Name";
        case 0x00000050: return "Application Label";
        case 0x00000057: return "Track 2 Equivalent Data";
        case 0x0000005a: return "Application Primary Account Number (PAN)";
        case 0x00000061: return "Application Template";
        case 0x0000006f: return "File Control Information (FCI) Template";
        case 0x00000070: return "READ RECORD Response Message Template";
        case 0x00000071: return "Issuer Script Template 1";
        case 0x00000072: return "Issuer Script Template 2";
        case 0x00000073: return "Directory Discretionary Template";
        case 0x00000077: return "Response Message Template Format 2";
        case 0x00000080: return "Response Message Template Format 1";
        case 0x00000081: return "Amount, Authorised (Binary)";
        case 0x00000082: return "Application Interchange Profile";
        case 0x00000083: return "Command Template";
        case 0x00000084: return "Dedicated File (DF) Name";
        case 0x00000086: return "Issuer Script Command";
        case 0x00000087: return "Application Priority Indicator";
        case 0x00000088: return "Short File Identifier (SFI)";
        case 0x00000089: return "Authorisation Code";
        case 0x0000008a: return "Authorisation Response Code";
        case 0x0000008c: return "Card Risk Management Data Object List 1 (CDOL1)";
        case 0x0000008d: return "Card Risk Management Data Object List 2 (CDOL2)";
        case 0x0000008e: return "Cardholder Verification Method (CVM) List";
        case 0x0000008f: return "Certification Authority Public Key Index";
        case 0x00000090: return "Issuer Public Key Certificate";
        case 0x00000091: return "Issuer Authentication Data";
        case 0x00000092: return "Issuer Public Key Remainder";
        case 0x00000093: return "Signed Static Application Data";
        case 0x00000094: return "Application File Locator (AFL)";
        case 0x00000095: return "Terminal Verification Results";
        case 0x00000097: return "Transaction Certificate Data Object List (TDOL)";
        case 0x00000098: return "Transaction Certificate (TC) Hash Value";
        case 0x00000099: return "Transaction Personal Identification Number (PIN) Data";
        case 0x0000009a: return "Transaction Date";
        case 0x0000009b: return "Transaction Status Information";
        case 0x0000009c: return "Transaction Type";
        case 0x0000009d: return "Directory Definition File (DDF) Name";
        case 0x000000a1: return "Biometric Header Template (BHT)";
        case 0x000000a5: return "File Control Information (FCI) Proprietary Template";
        case 0x00005f20: return "Cardholder Name";
        case 0x00005f24: return "Application Expiration Date";
        case 0x00005f25: return "Application Effective Date";
        case 0x00005f28: return "Issuer Country Code";
        case 0x00005f2a: return "Transaction Currency Code";
        case 0x00005f2d: return "Language Preference";
        case 0x00005f30: return "Service Code";
        case 0x00005f34: return "Application Primary Account Number (PAN) Sequence Number";
        case 0x00005f36: return "Transaction Currency Exponent";
        case 0x00005f50: return "Issuer URL";
        case 0x00005f53: return "International Bank Account Number (IBAN)";
        case 0x00005f54: return "Bank Identifier Code (BIC)";
        case 0x00005f55: return "Issuer Country Code (alpha2 format)";
        case 0x00005f56: return "Issuer Country Code (alpha3 format)";
        case 0x00005f57: return "Account Type";
        case 0x00007f60: return "Biometric Information Template (BIT)";
        case 0x00009f01: return "Acquirer Identifier";
        case 0x00009f02: return "Amount, Authorised (Numeric)";
        case 0x00009f03: return "Amount, Other (Numeric)";
        case 0x00009f04: return "Amount, Other (Binary)";
        case 0x00009f05: return "Application Discretionary Data";
        case 0x00009f06: return "Application Identifier (AID) – terminal";
        case 0x00009f07: return "Application Usage Control";
        case 0x00009f08: return "Application Version Number";
        case 0x00009f09: return "Application Version Number";
        case 0x00009f0a: return "Application Selection Registered Proprietary Data (ASRPD)";
        case 0x00009f0b: return "Cardholder Name Extended";
        case 0x00009f0c: return "Issuer Identification Number Extended (IINE)";
        case 0x00009f0d: return "Issuer Action Code – Default";
        case 0x00009f0e: return "Issuer Action Code – Denial";
        case 0x00009f0f: return "Issuer Action Code – Online";
        case 0x00009f10: return "Issuer Application Data";
        case 0x00009f11: return "Issuer Code Table Index";
        case 0x00009f12: return "Application Preferred Name";
        case 0x00009f13: return "Last Online Application Transaction Counter (ATC) Register";
        case 0x00009f14: return "Lower Consecutive Offline Limit";
        case 0x00009f15: return "Merchant Category Code";
        case 0x00009f16: return "Merchant Identifier";
        case 0x00009f17: return "Personal Identification Number (PIN) Try Counter";
        case 0x00009f18: return "Issuer Script Identifier";
        case 0x00009f19: return "Token Requestor ID";
        case 0x00009f1a: return "Terminal Country Code";
        case 0x00009f1b: return "Terminal Floor Limit";
        case 0x00009f1c: return "Terminal Identification";
        case 0x00009f1d: return "Terminal Risk Management Data";
        case 0x00009f1e: return "Interface Device (IFD) Serial Number";
        case 0x00009f1f: return "Track 1 Discretionary Data";
        case 0x00009f20: return "Track 2 Discretionary Data";
        case 0x00009f21: return "Transaction Time";
        case 0x00009f22: return "Certification Authority Public Key Index";
        case 0x00009f23: return "Upper Consecutive Offline Limit";
        case 0x00009f24: return "Payment Account Reference (PAR)";
        case 0x00009f25: return "Last 4 Digits of PAN";
        case 0x00009f26: return "Application Cryptogram";
        case 0x00009f27: return "Cryptogram Information Data";
        case 0x00009f2d: return "ICC PIN Encipherment Public Key Certificate (RSA) or Integrated Circuit Card (ICC) Public Key Certificate for ODE (ECC)";
        case 0x00009f2e: return "ICC PIN Encipherment Public Key Exponent";
        case 0x00009f2f: return "ICC PIN Encipherment Public Key Remainder";
        case 0x00009f30: return "Biometric Terminal Capabilities";
        case 0x00009f31: return "Card BIT Group Template";
        case 0x00009f32: return "Issuer Public Key Exponent";
        case 0x00009f33: return "Terminal Capabilities";
        case 0x00009f34: return "Cardholder Verification Method (CVM) Results";
        case 0x00009f35: return "Terminal Type";
        case 0x00009f36: return "Application Transaction Counter (ATC)";
        case 0x00009f37: return "Unpredictable Number";
        case 0x00009f38: return "Processing Options Data Object List (PDOL)";
        case 0x00009f39: return "Point-of-Service (POS) Entry Mode";
        case 0x00009f3a: return "Amount, Reference Currency";
        case 0x00009f3b: return "Application Reference Currency";
        case 0x00009f3c: return "Transaction Reference Currency Code";
        case 0x00009f3d: return "Transaction Reference Currency Exponent";
        case 0x00009f40: return "Additional Terminal Capabilities";
        case 0x00009f41: return "Transaction Sequence Counter";
        case 0x00009f42: return "Application Currency Code";
        case 0x00009f43: return "Application Reference Currency Exponent";
        case 0x00009f44: return "Application Currency Exponent";
        case 0x00009f45: return "Data Authentication Code";
        case 0x00009f46: return "ICC Public Key Certificate";
        case 0x00009f47: return "ICC Public Key Exponent";
        case 0x00009f48: return "ICC Public Key Remainder";
        case 0x00009f49: return "Dynamic Data Authentication Data Object List (DDOL)";
        case 0x00009f4a: return "Static Data Authentication Tag List";
        case 0x00009f4b: return "Signed Dynamic Application Data";
        case 0x00009f4c: return "ICC Dynamic Number";
        case 0x00009f4d: return "Log Entry";
        case 0x00009f4e: return "Merchant Name and Location";
        case 0x00009f4f: return "Log Format";
        case 0x0000bf0c: return "File Control Information (FCI) Issuer Discretionary Data";
        case 0x0000bf4a: return "Offline BIT Group Template";
        case 0x0000bf4b: return "Online BIT Group Template";
        case 0x0000bf4c: return "Biometric Try Counters Template";
        case 0x0000bf4d: return "Preferred Attempts Template";
        case 0x0000bf4e: return "Biometric Verification Data Template";
        case 0x0000df50: return "Facial Try Counter";
        case 0x0000df51: return "Finger Try Counter";
        case 0x0000df52: return "Iris Try Counter";
        case 0x0000df53: return "Palm Try Counter";
        case 0x0000df54: return "Voice Try Counter";
        default:         return "Unknown";
    }
}

void tlvParse(
    std::vector<uint8_t> const& tlv,
    std::multimap<uint32_t, std::vector<uint8_t>>& data,
    std::string const& prefix)
{
    // https://www.openscdp.org/scripts/tutorial/emv/tlv.html

    for(auto it = tlv.begin(); it != tlv.end(); ) {
        bool constructed = false;
        if((*it & 0x20) == 0x20)
            constructed = true;

        uint32_t tag = 0;
        if((*it & 0x1f) != 0x1f)
            tag = *it;
        else if((*(it+1) & 0x80) != 0x80)
            tag = (*it << 8) | *(++it);
        else
            tag = (*it << 16) | (*(++it) << 8) | *(++it);
        ++it;

        uint16_t size = 0;
        if((*it & 0x80) != 0x80)
            size = *it;
        else if(*it == 0x81)
            size = *(++it);
        else if(*it == 0x82)
            size = (*(++it) << 8) | *(++it);
        ++it;

        std::vector<uint8_t> val(it, it+size);
        it += size;

        data.emplace(tag, val);

        LOG(info) << prefix
            << "0x" << tools::bytesToHex(tag)
            << ": "   << tools::bytesToHex(val)
            << " ("   << tagDescription(tag) << ")";

        if(constructed)
            tlvParse(val, data, "    "+prefix);
    }
}

}

void tlvParse(std::vector<uint8_t> const& tlv)
{
    std::multimap<uint32_t, std::vector<uint8_t>> data;
    return tlvParse(tlv, data, "");
}

void tlvParse(std::vector<uint8_t> const& tlv, std::multimap<uint32_t, std::vector<uint8_t>>& data)
{
    return tlvParse(tlv, data, "");
}
