// Copyright (c) 2009-2012 Bitcoin Developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2013 digitalcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "importprivkey <digitalcoinprivkey> [label]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();
    CKey key;
    bool fCompressed;

    if(strSecret.size() == 30) //tfg
    {
        SHA256_CTX shactx;
        unsigned char hash[32];

        string strTestAddress = strSecret + '?';

        SHA256_Init(&shactx);
        SHA256_Update(&shactx, strTestAddress.c_str(), strTestAddress.size());
        SHA256_Final(hash, &shactx);

        if (hash[0] != '\x00')
            throw JSONRPCError(-5,"Invalid private key");

        SHA256_Init(&shactx);
        SHA256_Update(&shactx, strSecret.c_str(), strSecret.size());
        SHA256_Final(hash, &shactx);

        CSecret secret(hash, hash+32);
        key.SetSecret(secret, fCompressed);
    }
    else
    {
        CBitcoinSecret vchSecret;

        bool fGood = vchSecret.SetString(strSecret);
        if (!fGood) throw JSONRPCError(-5,"Invalid private key");

        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
    }

    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(pwalletMain->mapAddressBook.count(CBitcoinAddress(vchAddress).Get()))
            throw JSONRPCError(-5,"Address already in wallet");

        pwalletMain->MarkDirty();

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(-4,"Error adding key to wallet");

        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
        pwalletMain->ReacceptWalletTransactions();
    }

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
	    "dumpprivkey <digitalcoinaddress>\n"
	    "Reveals the private key corresponding to <digitalcoinaddress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
	throw JSONRPCError(-5, "Invalid digitalcoin address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(-3, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}
