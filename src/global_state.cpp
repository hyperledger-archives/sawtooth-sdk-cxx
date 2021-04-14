/*
 Copyright 2017 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

#include <exception>
#include <string>

#include <log4cxx/logger.h>
#include "proto/state_context.pb.h"
#include "proto/client_state.pb.h"
#include "proto/client_block.pb.h"
#include "proto/events.pb.h"
#include "proto/block.pb.h"

#include "sawtooth/global_state.h"
#include "exceptions.h"
#include "sawtooth/message_stream.h"
#include "sawtooth_sdk.h"
#include "sawtooth/future_message.h"
#include "sawtooth/message_dispatcher.h"
#undef ERROR

namespace sawtooth {

static log4cxx::LoggerPtr  logger(log4cxx::Logger::getLogger
    ("sawtooth.GlobalState"));


GlobalStateImpl::GlobalStateImpl(
    const MessageStreamPtr& message_stream, const std::string& context_id, ::google::protobuf::uint64 newTip):
    message_stream(message_stream), context_id(context_id), tip(newTip) {}

bool GlobalStateImpl::GetState(std::string* out_value, const std::string& address) const {
    std::unordered_map<std::string, std::string> out;
    std::vector<std::string> addresses = { address };

    this->GetState(&out, addresses);
    auto value = out.find(address);
    if( value != out.end()) {
        *out_value = (*value).second;
        return true;
    }
    return false;
}

void GlobalStateImpl::GetState(
        std::unordered_map<std::string, std::string>* out_values,
        const std::vector<std::string>& addresses) const {
    if (!out_values) {
        throw std::runtime_error("Expecting valid pointer passed to " \
            "out_values");
    }
    // create a reference to provide easier access to the return value
    std::unordered_map<std::string, std::string>& out_values_ref(*out_values);
    out_values_ref.clear();

    TpStateGetRequest request;
    TpStateGetResponse response;
    request.set_context_id(this->context_id);
    for (auto addr : addresses) {
      request.add_addresses(addr);
    }

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::TP_STATE_GET_REQUEST, request);
    future->GetMessage(Message::TP_STATE_GET_RESPONSE, &response);

    if(response.status() == TpStateGetResponse::AUTHORIZATION_ERROR){
        std::stringstream error;
        error << "State Get Authorization error. Check transaction inputs.";
        throw sawtooth::InvalidTransaction(error.str());
    }

    if ( response.entries_size() > 0 ) {
        for (const auto& entry : response.entries()) {
            out_values_ref[entry.address()] = entry.data();
        }
    }
}

void GlobalStateImpl::GetStatesByPrefix(const std::string& address, std::string* root, std::vector<KeyValue>* out_values) const {
    assert(out_values != nullptr && out_values->size() == 0);

    ClientStateListRequest request;
    ClientStateListResponse response;

    request.set_state_root(root->empty()? "": root->c_str());
    request.set_address(address);

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::CLIENT_STATE_LIST_REQUEST, request);
    future->GetMessage(Message::CLIENT_STATE_LIST_RESPONSE, &response);

    if (response.status() == ClientStateListResponse::NO_RESOURCE) {
        out_values->resize(0);
        return;
    }

    if (response.status() != ClientStateListResponse::OK) {
        std::stringstream error;
        error << "Failed to retrieve states by prefix";
        throw sawtooth::InvalidTransaction(error.str());
    }

    *root = response.paging().next();
    int num = response.entries_size();
    out_values->resize(num);

    for (int i = 0; i < num; ++i) {
        auto const& entry = response.entries(i);
        auto newKeyValue = KeyValue(entry.address(), entry.data());
        out_values->at(i).swap(newKeyValue);
    }
}

void GlobalStateImpl::GetSigByNum(::google::protobuf::uint64 num, std::string* sig_out) const {
    assert(sig_out != nullptr);

    ClientBlockGetByNumRequest request;
    ClientBlockGetResponse response;

    request.set_block_num(num);

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::CLIENT_BLOCK_GET_BY_NUM_REQUEST, request);
    future->GetMessage(Message::CLIENT_BLOCK_GET_RESPONSE, &response);

    if (response.status() != ClientBlockGetResponse::OK) {
        std::stringstream error;
        error << "Failed to retrieve block by num";
        throw sawtooth::InvalidTransaction(error.str());
    }

    auto const& header_str = response.block().header();
    BlockHeader header;
    header.ParseFromString(header_str);
    header.block_num();

    *sig_out = header.signer_public_key();
}

void GlobalStateImpl::GetBlockById(const std::string& block_id, BlockInfo* header_out) const {
    assert(header_out != nullptr);

    ClientBlockGetByIdRequest request;
    ClientBlockGetResponse response;

    request.set_block_id(block_id);

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::CLIENT_BLOCK_GET_BY_ID_REQUEST, request);
    future->GetMessage(Message::CLIENT_BLOCK_GET_RESPONSE, &response);

    if (response.status() != ClientBlockGetResponse::OK) {
        std::stringstream error;
        error << "Failed to retrieve block by ID";
        throw sawtooth::InvalidTransaction(error.str());
    }

    auto const& block = response.block();
    auto const& header_str = block.header();
    BlockHeader header;
    header.ParseFromString(header_str);
    BlockInfo info = BlockInfo(header.block_num(), block.header_signature(),  header.previous_block_id(), header.signer_public_key());
    *header_out = std::move(info);
}


void GlobalStateImpl::GetRewardBlockSignatures(const std::string& block_id, std::vector<std::string> &signatures, ::google::protobuf::uint64 first_pred, ::google::protobuf::uint64 last_pred) const {

    ClientRewardBlockListRequest request;
    ClientRewardBlockListResponse response;

    request.set_head_id(block_id);
    request.set_first_predecessor_height(first_pred);
    request.set_last_predecessor_height(last_pred);


    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::CLIENT_REWARD_BLOCK_LIST_REQUEST, request);
    future->GetMessage(Message::CLIENT_REWARD_BLOCK_LIST_RESPONSE, &response);

    if (response.status() != ClientRewardBlockListResponse::OK) {
        std::stringstream error;
        error << "Failed to retrieve Reward Block List";

        throw sawtooth::InvalidTransaction(error.str());
    }
    
    auto const& blocks = response.blocks();
    for(auto block : blocks){
        auto const& header_str = block.header();
        BlockHeader header;
        header.ParseFromString(header_str);
        signatures.push_back(header.signer_public_key());
    }
}

void GlobalStateImpl::SetState(const std::string& address, const std::string& value) const {
    std::vector<KeyValue> kv_pairs = { make_pair(address, value) };
    this->SetState(kv_pairs);
}

void GlobalStateImpl::SetState(const std::vector<KeyValue>& kv_pairs) const {
    TpStateSetRequest request;
    TpStateSetResponse response;
    request.set_context_id(this->context_id);
    for (auto kv : kv_pairs) {
        TpStateEntry* ent = request.add_entries();
        ent->set_address(kv.first);
        ent->set_data(kv.second);
    }

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::TP_STATE_SET_REQUEST, request);
    future->GetMessage(Message::TP_STATE_SET_RESPONSE, &response);

    if(response.status() == TpStateSetResponse::AUTHORIZATION_ERROR){
        std::stringstream error;
        error << "State Set Authorization error. Check transaction outputs.";
        throw sawtooth::InvalidTransaction(error.str());
    }

}


void GlobalStateImpl::DeleteState(
        const std::string& address) const {
    std::vector<std::string> addrs = { address };
    this->DeleteState(addrs);
}

void GlobalStateImpl::DeleteState(const std::vector<std::string>& addresses) const {
    TpStateDeleteRequest request;
    TpStateDeleteResponse response;
    request.set_context_id(this->context_id);
    for (auto& addr : addresses) {
        request.add_addresses(addr);
    }

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::TP_STATE_DELETE_REQUEST, request);
    future->GetMessage(Message::TP_STATE_DELETE_RESPONSE, &response);
}


void GlobalStateImpl::AddEvent(const std::string& event_type ,
	const std::vector<KeyValue>& kv_pairs , const std::string& event_data) const {
    Event *event = new Event();
    event->set_event_type(event_type);
    for (auto kv : kv_pairs) {
        Event_Attribute* attr = event->add_attributes();
        attr->set_key(kv.first);
        attr->set_value(kv.second);
    }
    event->set_data(event_data);

    TpEventAddRequest request;
    TpEventAddResponse response;
    request.set_context_id(this->context_id);
    request.set_allocated_event(event);

    FutureMessagePtr future = this->message_stream->SendMessage(
        Message::TP_EVENT_ADD_REQUEST, request);
    future->GetMessage(Message::TP_EVENT_ADD_RESPONSE, &response);

    if(response.status() == TpEventAddResponse::ERROR){
        std::stringstream error;
        error << "Failed to add event for Event Type = " << event_type << " ; Event Data = " << event_data;
        throw sawtooth::InvalidTransaction(error.str());
    }
}

::google::protobuf::uint64 GlobalStateImpl::GetTip() const
{
    return tip;
}

}  // namespace sawtooth

