#include <map>
#include <string>
#include <vector>

#include <loguru.hpp>
#include <tools/bytes.hpp>

#include "emv/tlv.hpp"

int read()
{
    std::string pse = "2PAY.SYS.DDF01";
    std::vector<uint8_t> cmdPse = { 0x00, 0xa4, 0x04, 0x00, 0x00 };
    cmdPse[4] = pse.size();
    cmdPse.insert(cmdPse.end(), pse.begin(), pse.end());

    // Transfer T1...

    std::vector<uint8_t> rsp;
    if(rsp.size() < 2 || *(rsp.end()-2) != 0x90 || *(rsp.end()-1) != 0x00)
        return 1;
    rsp.resize(rsp.size()-2);

    std::multimap<uint32_t, std::vector<uint8_t>> data;

    LOG(info) << "PSE: " << tools::bytesToHex(rsp);
    tlvParse(rsp, data);

    auto search = data.find(0x00000084); // DF
    if(search != data.end()) {
        std::string label{ search->second.begin(), search->second.end() };
        LOG(info) << "Dedicated File: " << label;
    }

    search = data.find(0x0000004f); // ADF
    if(search == data.end())
        return 1;

    std::vector<uint8_t> aid = search->second;
    std::vector<uint8_t> cmdAid = { 0x00, 0xa4, 0x04, 0x00, 0x00 };
    cmdAid[4] = aid.size();
    cmdAid.insert(cmdAid.end(), aid.begin(), aid.end());

    // Transfer T1...

    if(rsp.size() < 2 || *(rsp.end()-2) != 0x90 || *(rsp.end()-1) != 0x00)
        return 1;
    rsp.resize(rsp.size()-2);

    LOG(info) << "Select: " << tools::bytesToHex(rsp);
    tlvParse(rsp, data);

    search = data.find(0x00000050); // Application Label
    if(search != data.end()) {
        std::string label{ search->second.begin(), search->second.end() };
        LOG(info) << "Application Label: " << label;
    }

    search = data.find(0x00005f2d); // Language Preference
    if(search != data.end()) {
        std::string label{ search->second.begin(), search->second.end() };
        LOG(info) << "Language Preference: " << label;
    }

    search = data.find(0x00009f38); // PDOL
    std::vector<uint8_t> gpo;
    if(search != data.end()) {
        std::vector<uint8_t> pdol = search->second;
        for(auto it = pdol.begin(); it != pdol.end(); ) {
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

            std::vector<uint8_t> val;
            switch(tag) {
                case 0x00000095: // Terminal Verification Results (5 byte, https://en.wikipedia.org/wiki/Terminal_verification_results)
                break;

                case 0x0000009a: // Transaction Date (3 byte, YYMMDD)
                    val = { 0x23, 0x07, 0x13 };
                break;

                case 0x00009f02: // Amount, Authorised (Numeric) (6 byte, BCD)
                case 0x00009f03: // Amount, Other (Numeric) (6 byte, BCD)
                    val = { 0x00, 0x00, 0x00, 0x00, 0x10, 0x00 };
                break;

                case 0x00005f2a: // Transaction Currency Code (2 byte)
                case 0x00009f1a: // Terminal Country Code (2 byte)
                    val = { 0x06, 0x43 };
                break;

                case 0x00009f37: // Unpredictable Number (4 byte)
                    val = { 0x01, 0x23, 0x45, 0x67 };
                break;

                case 0x00009f66: // TTQ (4 byte, https://emv.cool/2020/12/24/Terminal-Transaction-Qualifiers-TTQ-9F66-qPBOC)
                   val = { 0x20, 0x00, 0x00, 0x00 };
                break;
            }
            gpo.insert(gpo.end(), val.begin(), val.end());
        }
    }

    std::vector<uint8_t> cmdGpo = { 0x80, 0xa8, 0x00, 0x00, 0x02, 0x83, 0x00 };
    if(gpo.size()) {
        cmdGpo[4] = gpo.size()+2;
        cmdGpo[6] = gpo.size();
        cmdGpo.insert(cmdGpo.end(), gpo.begin(), gpo.end());
    }

    // Transfer T1...

    if(rsp.size() < 2 || *(rsp.end()-2) != 0x90 || *(rsp.end()-1) != 0x00)
        LOG(error) << "GPO error: " << tools::bytesToHex(rsp);
        // return 1;
    rsp.resize(rsp.size()-2);

    LOG(info) << "GPO: " << tools::bytesToHex(rsp);
    tlvParse(rsp, data);

    std::vector<uint8_t> cmdReadRecord = { 0x00, 0xb2, 0x00, 0x00, 0x00 };
    for(int j = 0; j < 10; ++j)
        for(int i = 0; i < 10; ++i) {
            cmdReadRecord[2] = i;
            cmdReadRecord[3] = (j << 3) + 4;

            // Transfer T1...

            if(rsp.size() < 2 || *(rsp.end()-2) != 0x90 || *(rsp.end()-1) != 0x00)
                continue;
            rsp.resize(rsp.size()-2);

            LOG(info) << "Read: " << j << " " << i;

            tlvParse(rsp, data);
        }

    return 0;
}
