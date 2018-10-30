/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 *
 * Project 2 completed: 20181001
 * Project 3 modified: 20181030
 * asdfchlwnsgy1236
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

#include <E/E_TimeUtil.hpp>

// defines used for making packets
#define TCP_DATA_OFFSET_MIN 0x50
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_WINDOW_SIZE 0xc800

// define used for closing the connection
#define TCP_MSL TimeUtil::makeTime(5, TimeUtil::MSEC)

namespace E
{
record::record(UUID uuid, int pid, int sock, unsigned int backlog, unsigned int seq, unsigned int nextseq, sockstate state,
		unsigned int srcaddr, unsigned short srcport, unsigned int dstaddr, unsigned short dstport,
		sockinvec invector, bool sleeping):
		uuid(uuid), pid(pid), sock(sock), backlog(backlog), seq(seq), nextseq(nextseq), state(state),
		addr(), otheraddr(), acceptaddr(nullptr), acceptaddrsize(nullptr),
		pending(), established(), accepted(),
		invector(invector), sleeping(sleeping){
	// straightforward initialization with values given except for vectors, which are zero initialized
	// Note: must remember that the address and port arguments passed on to this need to be in network order
	addr.sin_family = AF_INET;
	addr.sin_port = srcport;
	addr.sin_addr.s_addr = srcaddr;
	otheraddr.sin_family = AF_INET;
	otheraddr.sin_port = dstport;
	otheraddr.sin_addr.s_addr = dstaddr;
}

record::record():
		record(0, -1, -1, 0, 0, 0, sockstate::CLOSED,
				0, 0, 0, 0,
				sockinvec::IN_BINDRECS, false){
	// from the shadows I come
}

record::record(record const &r):
		uuid(r.uuid), pid(r.pid), sock(r.sock), backlog(r.backlog), seq(r.seq), nextseq(r.nextseq), state(r.state),
		addr(), otheraddr(), acceptaddr(r.acceptaddr), acceptaddrsize(r.acceptaddrsize),
		pending(), established(), accepted(),
		invector(r.invector), sleeping(r.sleeping){
	// straightforward copy except for vectors, which are copied manually
	addr.sin_family = r.addr.sin_family;
	addr.sin_port = r.addr.sin_port;
	addr.sin_addr.s_addr = r.addr.sin_addr.s_addr;
	otheraddr.sin_family = r.otheraddr.sin_family;
	otheraddr.sin_port = r.otheraddr.sin_port;
	otheraddr.sin_addr.s_addr = r.otheraddr.sin_addr.s_addr;
	for(auto a: r.pending){
		pending.push_back(new record(*a));
	}
	for(auto a: r.established){
		established.push_back(new record(*a));
	}
	for(auto a: r.accepted){
		accepted.push_back(new record(*a));
	}
}

record::record(record &&r):
		uuid(r.uuid), pid(r.pid), sock(r.sock), backlog(r.backlog), seq(r.seq), nextseq(r.nextseq), state(r.state),
		addr(), otheraddr(), acceptaddr(r.acceptaddr), acceptaddrsize(r.acceptaddrsize),
		pending(std::move(r.pending)), established(std::move(r.established)), accepted(std::move(r.accepted)),
		invector(r.invector), sleeping(r.sleeping){
	// straightforward copy except for vectors, which are moved using move constructors
	addr.sin_family = r.addr.sin_family;
	addr.sin_port = r.addr.sin_port;
	addr.sin_addr.s_addr = r.addr.sin_addr.s_addr;
	otheraddr.sin_family = r.otheraddr.sin_family;
	otheraddr.sin_port = r.otheraddr.sin_port;
	otheraddr.sin_addr.s_addr = r.otheraddr.sin_addr.s_addr;
}

record &record::operator=(record const &r){
	// check for self-assignment
	if(this != &r){
		// straightforward copy except for vectors, which are copied manually
		uuid = r.uuid;
		pid = r.pid;
		sock = r.sock;
		backlog = r.backlog;
		seq = r.seq;
		nextseq = r.nextseq;
		state = r.state;
		addr.sin_family = r.addr.sin_family;
		addr.sin_port = r.addr.sin_port;
		addr.sin_addr.s_addr = r.addr.sin_addr.s_addr;
		otheraddr.sin_family = r.otheraddr.sin_family;
		otheraddr.sin_port = r.otheraddr.sin_port;
		otheraddr.sin_addr.s_addr = r.otheraddr.sin_addr.s_addr;
		acceptaddr = r.acceptaddr;
		acceptaddrsize = r.acceptaddrsize;
		for(auto a: pending){
			delete a;
		}
		pending.clear();
		for(auto a: r.pending){
			pending.push_back(new record(*a));
		}
		for(auto a: established){
			delete a;
		}
		established.clear();
		for(auto a: r.established){
			established.push_back(new record(*a));
		}
		for(auto a: accepted){
			delete a;
		}
		accepted.clear();
		for(auto a: r.accepted){
			accepted.push_back(new record(*a));
		}
		invector = r.invector;
		sleeping = r.sleeping;
	}

	return *this;
}

record &record::operator=(record &&r){
	// check for self-assignment
	if(this != &r){
		// straightforward copy except for vectors, which are moved using move assignment
		uuid = r.uuid;
		pid = r.pid;
		sock = r.sock;
		backlog = r.backlog;
		seq = r.seq;
		nextseq = r.nextseq;
		state = r.state;
		addr.sin_family = r.addr.sin_family;
		addr.sin_port = r.addr.sin_port;
		addr.sin_addr.s_addr = r.addr.sin_addr.s_addr;
		otheraddr.sin_family = r.otheraddr.sin_family;
		otheraddr.sin_port = r.otheraddr.sin_port;
		otheraddr.sin_addr.s_addr = r.otheraddr.sin_addr.s_addr;
		acceptaddr = r.acceptaddr;
		acceptaddrsize = r.acceptaddrsize;
		for(auto a: pending){
			delete a;
		}
		pending.clear();
		pending = std::move(r.pending);
		for(auto a: established){
			delete a;
		}
		established.clear();
		established = std::move(r.established);
		for(auto a: accepted){
			delete a;
		}
		accepted.clear();
		accepted = std::move(r.accepted);
		invector = r.invector;
		sleeping = r.sleeping;
	}

	return *this;
}

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem()),
		bindrecs(), randomseq(0), randomport(8192)
{
}

TCPAssignment::~TCPAssignment()
{
}

void TCPAssignment::initialize()
{
}

void TCPAssignment::finalize()
{
}

std::vector<record *>::iterator TCPAssignment::findInRecords(int pid, int sock){
	// go through the list of bound sockets and accepted connections to find the given socket
	for(auto a = bindrecs.begin(); a != bindrecs.end(); a++){
		if((*a)->pid == pid && (*a)->sock == sock){
			// record found
			return a;
		}

		for(auto b = (*a)->accepted.begin(); b != (*a)->accepted.end(); b++){
			if((*b)->pid == pid && (*b)->sock == sock){
				// record found
				return b;
			}
		}
	}

	// record not found
	return bindrecs.end();
}

bool TCPAssignment::recordMatchesAddrs(std::vector<record *>::iterator index, unsigned int anyaddr,
		unsigned int srcaddr, unsigned short srcport,
		unsigned int dstaddr, unsigned short dstport){
	// check using the rules for overlapping sockets
	return (*index)->addr.sin_port == srcport &&
				(*index)->otheraddr.sin_port == dstport &&
				((*index)->addr.sin_addr.s_addr == srcaddr ||
				(*index)->addr.sin_addr.s_addr == anyaddr ||
				srcaddr == anyaddr) &&
				((*index)->otheraddr.sin_addr.s_addr == dstaddr ||
				(*index)->otheraddr.sin_addr.s_addr == anyaddr ||
				dstaddr == anyaddr);
}

std::vector<record *>::iterator TCPAssignment::findInRecords(unsigned int srcaddr, unsigned short srcport,
		unsigned int dstaddr, unsigned short dstport){
	unsigned int anyaddr = htonl(INADDR_ANY);

	// go through the list of bound sockets
	for(auto a = bindrecs.begin(); a != bindrecs.end(); a++){
		if(recordMatchesAddrs(a, anyaddr, srcaddr, srcport, dstaddr, dstport)){
			return a;
		}

		// go through the list of pending connections to find the matching record
		for(auto b = (*a)->pending.begin(); b != (*a)->pending.end(); b++){
			if(recordMatchesAddrs(b, anyaddr, srcaddr, srcport, dstaddr, dstport)){
				// record found
				return b;
			}
		}

		// go through the list of established connections to find the matching record
		for(auto b = (*a)->established.begin(); b != (*a)->established.end(); b++){
			if(recordMatchesAddrs(b, anyaddr, srcaddr, srcport, dstaddr, dstport)){
				// record found
				return b;
			}
		}

		// go through the list of accepted connections to find the matching record
		for(auto b = (*a)->accepted.begin(); b != (*a)->accepted.end(); b++){
			if(recordMatchesAddrs(b, anyaddr, srcaddr, srcport, dstaddr, dstport)){
				// record found
				return b;
			}
		}
	}

	// record not found
	return bindrecs.end();
}

std::vector<record *>::iterator TCPAssignment::findInRecords(unsigned int srcaddr, unsigned short srcport){
	unsigned int anyaddr = htonl(INADDR_ANY);

	// go through the list of bound sockets
	for(auto a = bindrecs.begin(); a != bindrecs.end(); a++){
		if((*a)->addr.sin_port == srcport &&
				((*a)->addr.sin_addr.s_addr == srcaddr ||
				(*a)->addr.sin_addr.s_addr == anyaddr ||
				srcaddr == anyaddr)){
			// record found
			return a;
		}
	}

	// record not found
	return bindrecs.end();
}

unsigned short TCPAssignment::calculateChecksum(Packet *packet){
	unsigned int srcaddr, dstaddr;
	size_t tcplength = packet->getSize() - 34;
	unsigned char *tcpseg = (unsigned char *)malloc(tcplength);

	// extract the required parts from the packet
	packet->readData(26, &srcaddr, 4);
	packet->readData(30, &dstaddr, 4);
	packet->readData(34, tcpseg, tcplength);

	// use the provided TCP checksum function to get the checksum
	unsigned short checksum = htons(~NetworkUtil::tcp_sum(srcaddr, dstaddr, tcpseg, tcplength));

	// free memory allocated through malloc()
	free(tcpseg);

	// checksum calculation complete
	return checksum;
}

Packet *TCPAssignment::makePacket(size_t datasize, record const *rec, unsigned int ack,
		unsigned char dataoffset, unsigned char flags, unsigned short windowsize, void *data){
	size_t headersize = 34 + (dataoffset >> 4) * 4;

	// allocate and fill in the packet with the header data and payload (if the payload exists)
	Packet *packet = this->allocatePacket(headersize + (data == nullptr ? 0 : datasize));
	packet->writeData(26, &rec->addr.sin_addr.s_addr, 4);
	packet->writeData(30, &rec->otheraddr.sin_addr.s_addr, 4);
	packet->writeData(34, &rec->addr.sin_port, 2);
	packet->writeData(36, &rec->otheraddr.sin_port, 2);
	packet->writeData(38, &rec->seq, 4);
	packet->writeData(42, &ack, 4);
	packet->writeData(46, &dataoffset, 1);
	packet->writeData(47, &flags, 1);
	packet->writeData(48, &windowsize, 2);
	if(datasize > 0 && data != nullptr){
		packet->writeData(headersize, data, datasize);
	}

	// calculate the checksum and fill in the checksum field
	unsigned short checksum = calculateChecksum(packet);
	packet->writeData(50, &checksum, 2);

	// packet preparation complete
	return packet;
}

void TCPAssignment::eraseFromRecords(std::vector<record *>::iterator index,
		std::vector<record *>::iterator parentindex){
	// deallocate the socket record and then remove it from the appropriate list
	sockinvec forswitch = (*index)->invector;
	delete *index;
	switch(forswitch){
		case sockinvec::IN_BINDRECS:
			bindrecs.erase(index);

			break;
		case sockinvec::IN_PENDING:
			(*parentindex)->pending.erase(index);

			break;
		case sockinvec::IN_ESTABLISHED:
			(*parentindex)->established.erase(index);

			break;
		case sockinvec::IN_ACCEPTED:
			(*parentindex)->accepted.erase(index);

			break;
		default:
			break;
	}
}

void TCPAssignment::printRecord(record const *rec){
	std::cout << "[DEBUG] uuid: " << rec->uuid << std::endl;
	std::cout << "[DEBUG] pid: " << rec->pid << std::endl;
	std::cout << "[DEBUG] sock: " << rec->sock << std::endl;
	std::cout << "[DEBUG] backlog: " << rec->backlog << std::endl;
	std::cout << "[DEBUG] seq: " << rec->seq << std::endl;
	std::cout << "[DEBUG] nextseq: " << rec->nextseq << std::endl;
	std::cout << "[DEBUG] state: " << (int)rec->state << std::endl;
	std::cout << "[DEBUG] addr.sin_family: " << rec->addr.sin_family << std::endl;
	std::cout << "[DEBUG] addr.sin_port: " << rec->addr.sin_port << std::endl;
	std::cout << "[DEBUG] addr.sin_addr.s_addr: " << rec->addr.sin_addr.s_addr << std::endl;
	std::cout << "[DEBUG] otheraddr.sin_family: " << rec->otheraddr.sin_family << std::endl;
	std::cout << "[DEBUG] otheraddr.sin_port: " << rec->otheraddr.sin_port << std::endl;
	std::cout << "[DEBUG] otheraddr.sin_addr.s_addr: " << rec->otheraddr.sin_addr.s_addr << std::endl;
	std::cout << "[DEBUG] pending: " << *((unsigned long *)&rec->pending) <<
			" " << *((unsigned long *)&rec->pending + 1) <<
			" " << *((unsigned long *)&rec->pending + 2) << std::endl;
	std::cout << "[DEBUG] established: " << *((unsigned long *)&rec->established) <<
			" " << *((unsigned long *)&rec->established + 1) <<
			" " << *((unsigned long *)&rec->established + 2) << std::endl;
	std::cout << "[DEBUG] accepted: " << *((unsigned long *)&rec->accepted) <<
			" " << *((unsigned long *)&rec->accepted + 1) <<
			" " << *((unsigned long *)&rec->accepted + 2) << std::endl;
	std::cout << "[DEBUG] invector: " << (int)rec->invector << std::endl;
	std::cout << "[DEBUG] sleeping: " << rec->sleeping << std::endl;
}

void TCPAssignment::syscall_socket(UUID uuid, int pid, int param1, int param2){
	// create a file descriptor and use the system's return call to pass it on
	this->returnSystemCall(uuid, this->createFileDescriptor(pid));
}

void TCPAssignment::syscall_close(UUID uuid, int pid, int param1){
	// search for the socket in the socket records and if not found, simply close it;
	// otherwise, start the connection teardown sequence unless the socket state is CLOSED or LISTEN
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		// close the socket
		this->removeFileDescriptor(pid, param1);

		// no errors
		this->returnSystemCall(uuid, 0);
	}
	else if((*index)->state == sockstate::CLOSED || (*index)->state == sockstate::LISTEN){
		// closed sockets do not exist in the socket records, so this is a socket that only had bind() called on it,
		// and close() seems to be called on the server's listening socket only after all other connections are closed,
		// so simply close, deallocate, and remove it from the list of bound sockets
		this->removeFileDescriptor(pid, param1);
		delete *index;
		bindrecs.erase(index);

		// no errors
		this->returnSystemCall(uuid, 0);
	}
	else if((*index)->state == sockstate::ESTABLISHED || (*index)->state == sockstate::CLOSE_WAIT){
		// either a client or the server's child socket, so send a FIN packet to signal the beginning of the end
		(*index)->uuid = uuid;
		(*index)->state = (*index)->state == sockstate::ESTABLISHED ? sockstate::FIN_WAIT_1 : sockstate::LAST_ACK;
		(*index)->nextseq = ntohl((*index)->seq) + 1;
		(*index)->sleeping = true;
		this->sendPacket("IPv4", makePacket(0, *index, (*index)->seq,
				TCP_DATA_OFFSET_MIN, TCP_FIN, htons(TCP_WINDOW_SIZE), nullptr));
	}
}

//void TCPAssignment::syscall_read(UUID uuid, int pid, int param1, void *param2, int param3){
//}

//void TCPAssignment::syscall_write(UUID uuid, int pid, int param1, void *param2, int param3){
//}

void TCPAssignment::syscall_connect(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t param3){
	sockaddr_in *addr = (sockaddr_in *)param2;

	// search for the socket in the socket records and if not found, implicitly bind the socket
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		unsigned int srcaddr, anyaddr = htonl(INADDR_ANY);

		// get the local address for the implicit bind
		int interfaceindex = this->getHost()->getRoutingTable((unsigned char const *)&addr->sin_addr.s_addr);
		this->getHost()->getIPAddr((unsigned char *)&srcaddr, interfaceindex);

		// look for a useable port
		bool portnotfound = true;
		while(portnotfound){
			portnotfound = false;
			for(auto a: bindrecs){
				if(a->addr.sin_port == randomport &&
						(a->addr.sin_addr.s_addr == srcaddr ||
						a->addr.sin_addr.s_addr == anyaddr ||
						srcaddr == anyaddr)){
					randomport++;
					portnotfound = true;
					break;
				}
			}
		}

		// make the socket record that represents the implicitly bound socket
		bindrecs.push_back(new record(0, pid, param1, 0, 0, 0, sockstate::CLOSED,
				srcaddr, htons(randomport++), 0, 0,
				sockinvec::IN_BINDRECS, false));

		// update the iterator to point to the newly created record for the next step
		index = findInRecords(pid, param1);
	}

	// update the socket record for the connection setup sequence, then send a SYN packet to start the sequence
	(*index)->uuid = uuid;
	(*index)->seq = htonl(randomseq);
	(*index)->nextseq = randomseq + 1;
	(*index)->state = sockstate::SYN_SENT;
	(*index)->otheraddr.sin_port = addr->sin_port;
	(*index)->otheraddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	(*index)->invector = sockinvec::IN_BINDRECS;
	(*index)->sleeping = true;
	this->sendPacket("IPv4", makePacket(0, *index, htonl(randomseq),
			TCP_DATA_OFFSET_MIN, TCP_SYN, htons(TCP_WINDOW_SIZE), nullptr));
}

void TCPAssignment::syscall_listen(UUID uuid, int pid, int param1, int param2){
	// search for the socket in the socket records and if not found, abort the function
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		// error: socket could not be found
		this->returnSystemCall(uuid, -1);
		return;
	}

	// set the backlog of the socket and set the state to LISTEN to allow it to react to incoming packets
	(*index)->backlog = param2;
	(*index)->state = sockstate::LISTEN;

	// no errors
	this->returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_accept(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3){
	// search for the socket in the socket records and if not found, abort the function
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		// error: socket could not be found
		this->returnSystemCall(uuid, -1);
		return;
	}

	// if there is an established connection, consume it and return immediately;
	// otherwise, wait for a connection to be established
	if(!(*index)->established.empty()){
		// get the first established connection, assign a new socket file descriptor to it,
		// fill the given address structure with the client's address, set the length,
		// and move it to the accepted connections list
		auto toaccept = (*index)->established.begin();
		int sock = this->createFileDescriptor((*toaccept)->pid);
		(*toaccept)->sock = sock;
		(*toaccept)->invector = sockinvec::IN_ACCEPTED;
		*param3 = std::min((socklen_t)sizeof((*toaccept)->otheraddr), *param3);
		memcpy(param2, &(*toaccept)->otheraddr, *param3);
		(*index)->accepted.push_back(std::move(*toaccept));
		(*index)->established.erase(toaccept);

		// return the socket file descriptor
		this->returnSystemCall(uuid, sock);
	}
	else{
		// preparation for waking this accept() call later
		(*index)->uuid = uuid;
		(*index)->acceptaddr = param2;
		(*index)->acceptaddrsize = param3;
		(*index)->sleeping = true;
	}
}

void TCPAssignment::syscall_bind(UUID uuid, int pid, int param1, sockaddr *param2, int param3){
	sockaddr_in *addr = (sockaddr_in *)param2;
	unsigned int anyaddr = htonl(INADDR_ANY);

	// check if there are any conflicts between the existing bound sockets and the given socket or address
	for(auto a: bindrecs){
		if(a->pid == pid && a->sock == param1 || a->addr.sin_port == addr->sin_port &&
				(a->addr.sin_addr.s_addr == addr->sin_addr.s_addr ||
				a->addr.sin_addr.s_addr == anyaddr || addr->sin_addr.s_addr == anyaddr)){
			// error: conflicting bound socket exists
			this->returnSystemCall(uuid, -1);
			return;
		}
	}

	// there are no conflicts, so add the socket to the bound sockets list
	bindrecs.push_back(new record(0, pid, param1, 0, 0, 0, sockstate::CLOSED,
			addr->sin_addr.s_addr, addr->sin_port, 0, 0,
			sockinvec::IN_BINDRECS, false));

	// no errors
	this->returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_getsockname(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3){
	// search for the socket and if not found, abort the function
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		// error: socket could not be found
		this->returnSystemCall(uuid, -1);
		return;
	}

	// fill the given address structure with the address and set the length
	*param3 = std::min((socklen_t)sizeof((*index)->addr), *param3);
	memcpy(param2, &(*index)->addr, *param3);

	// no errors
	this->returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_getpeername(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3){
	// search for the socket and if not found, abort the function
	auto index = findInRecords(pid, param1);
	if(index == bindrecs.end()){
		// error: socket could not be found
		this->returnSystemCall(uuid, -1);
		return;
	}

	// fill the given address structure with the peer's address and set the length
	*param3 = std::min((socklen_t)sizeof((*index)->otheraddr), *param3);
	memcpy(param2, &(*index)->otheraddr, *param3);

	// no errors
	this->returnSystemCall(uuid, 0);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	unsigned int srcaddr, dstaddr, seq, ack;
	unsigned short srcport, dstport;
	unsigned char dataoffset, flags;
	size_t datasize;
	void *data = nullptr;

	// extract the required information from the packet
	packet->readData(26, &srcaddr, 4);
	packet->readData(30, &dstaddr, 4);
	packet->readData(34, &srcport, 2);
	packet->readData(36, &dstport, 2);
	packet->readData(38, &seq, 4);
	packet->readData(42, &ack, 4);
	packet->readData(46, &dataoffset, 1);
	packet->readData(47, &flags, 1);
	datasize = packet->getSize() - 54;
	if(datasize > 0){
		data = malloc(datasize);
		packet->readData(34 + (dataoffset >> 4) * 4, data, datasize);
	}

	// check whether the checksum is valid and if it is not, exit the function
	if(calculateChecksum(packet) != 0){
		// free memory to prevent memory leak
		this->freePacket(packet);
		if(data != nullptr){
			free(data);
		}

		// seems unlikely to happen, considering the tests are done in a reliable environment
		return;
	}

	// free the received packet since it is no longer needed
	this->freePacket(packet);

	// change the byte order of the sequence and acknowledgment numbers to host order for further use
	seq = ntohl(seq);
	ack = ntohl(ack);

	// extract the required flag values from the flag byte
	bool finflag = flags & TCP_FIN,
			synflag = flags & TCP_SYN,
			rstflag = flags & TCP_RST,
//			pshflag = flags & TCP_PSH,
			ackflag = flags & TCP_ACK;

	// find the socket record corresponding to the swapped source and destination addresses and ports
	auto index = findInRecords(dstaddr, dstport, srcaddr, srcport);

	// find the socket record corresponding to the destination address and port in the server
	auto parentindex = findInRecords(dstaddr, dstport);

	// set the state variable for determining how to react to the received packet
	sockstate state = sockstate::CLOSED;
	if(index != bindrecs.end()){
		state = (*index)->state;
// XXX
//printRecord(*index);
	}
	else if(parentindex != bindrecs.end()){
		state = (*parentindex)->state;
// XXX
//printRecord(*parentindex);
	}

	// react depending on the state of the receiving socket and the received flags and data of the packet
	switch(state){
		case sockstate::CLOSED:
			// no packets (should be) received by a socket in this state
			break;
		case sockstate::LISTEN:
			// this is when the server first receives a connection setup request from a client
			if(synflag && !ackflag){
				// valid request, so make the socket record that represents this pending connection
				auto toadd = new record(0, (*parentindex)->pid, -1, 0, htonl(randomseq), randomseq + 1, sockstate::SYN_RCVD,
						dstaddr, dstport, srcaddr, srcport,
						sockinvec::IN_PENDING, false);

				// check if there is enough space in the backlog for a new connection
				if((*parentindex)->pending.size() < (*parentindex)->backlog){
					// there is, so add the socket record to the list of pending connections to the server
					(*parentindex)->pending.push_back(toadd);

					// send a SYN ACK packet back to the client
					this->sendPacket("IPv4", makePacket(0, toadd, htonl(seq + 1),
							TCP_DATA_OFFSET_MIN, TCP_SYN | TCP_ACK, htons(TCP_WINDOW_SIZE), nullptr));
				}
				else{
					// there is not, so send a RST packet back to the client
					this->sendPacket("IPv4", makePacket(0, toadd, htonl(seq + 1),
							TCP_DATA_OFFSET_MIN, TCP_RST, htons(TCP_WINDOW_SIZE), nullptr));
				}
			}

			break;
		case sockstate::SYN_SENT:
			// this is when the client receives a response to the connection setup request from the server
			if(synflag && ackflag && ack == (*index)->nextseq){
				// valid response, so update the socket record for data transfer
				// and send an ACK packet back to the server
				(*index)->seq = htonl(ack);
				(*index)->state = sockstate::ESTABLISHED;
				this->sendPacket("IPv4", makePacket(0, *index, htonl(seq + 1),
						TCP_DATA_OFFSET_MIN, TCP_ACK, htons(TCP_WINDOW_SIZE), nullptr));

				// notify the connect() call that no errors occurred
				(*index)->sleeping = false;
				this->returnSystemCall((*index)->uuid, 0);
			}
			else if(rstflag){
				// negative response, so abort the connection setup attempt
				(*index)->state = sockstate::CLOSED;

				// notify the connect() call that an error occurred
				(*index)->sleeping = false;
				this->returnSystemCall((*index)->uuid, -1);
			}

			break;
		case sockstate::SYN_RCVD:
			// this is when the server receives the response to complete the connection setup sequence from the client
			if(!synflag && ackflag && ack == (*index)->nextseq){
				// valid response, so update the socket record for data transfer
				(*index)->seq = htonl(ack);
				(*index)->state = sockstate::ESTABLISHED;

				// if an accept() call is waiting, have it consume this connection;
				// otherwise, ready this connection for future accept() calls
				if((*parentindex)->sleeping){
					// assign a new file descriptor to the connection,
					// fill the given address structure with the client's address, set the length,
					// and move it to the accepted connections list
					(*parentindex)->sleeping = false;
					int sock = this->createFileDescriptor((*index)->pid);
					(*index)->sock = sock;
					(*index)->invector = sockinvec::IN_ACCEPTED;
					*(*parentindex)->acceptaddrsize = std::min((socklen_t)sizeof((*index)->otheraddr), *(*parentindex)->acceptaddrsize);
					memcpy((*parentindex)->acceptaddr, &(*index)->otheraddr, *(*parentindex)->acceptaddrsize);
					(*parentindex)->accepted.push_back(std::move(*index));
					(*parentindex)->pending.erase(index);

					// notify the accept() call that no errors occurred and have it return the socket file descriptor
					this->returnSystemCall((*parentindex)->uuid, sock);
				}
				else{
					// move the connection to the established connections list
					(*index)->invector = sockinvec::IN_ESTABLISHED;
					(*parentindex)->established.push_back(std::move(*index));
					(*parentindex)->pending.erase(index);
				}
			}

			break;
		case sockstate::ESTABLISHED:
			// this is when the server's child socket first receives a connection teardown signal from the client
			if(finflag && !ackflag){
				// valid signal, so update the socket record for closing and send an ACK packet back to the client
				(*index)->state = sockstate::CLOSE_WAIT;
				this->sendPacket("IPv4", makePacket(0, *index, htonl(seq + 1),
						TCP_DATA_OFFSET_MIN, TCP_ACK, htons(TCP_WINDOW_SIZE), nullptr));
			}

			break;
		case sockstate::FIN_WAIT_1:
			// this is when the client receives the response for the connection teardown signal from the server
			if(!finflag && ackflag && ack == (*index)->nextseq){
				// valid response, so update the socket record for the next step in closing
				// and wait for the server's child to close
				(*index)->seq = htonl(ack);
				(*index)->state = sockstate::FIN_WAIT_2;
			}
			else if(finflag && !ackflag){
				// peer started connection teardown sequence at the same time,
				// so send an ACK packet back to the peer
				(*index)->nextseq = ntohl((*index)->seq) + 1;
				(*index)->state = sockstate::CLOSING;
				this->sendPacket("IPv4", makePacket(0, *index, htonl(seq + 1),
						TCP_DATA_OFFSET_MIN, TCP_ACK, htons(TCP_WINDOW_SIZE), nullptr));
			}

			break;
		case sockstate::CLOSE_WAIT:
			// no packets to deal with in this state (up to Project 3)
			break;
		case sockstate::FIN_WAIT_2:
			// this is when the client receives the signal that indicates the server's child socket is closing
			if(finflag && !ackflag){
				// valid signal, so update the socket record for the last stage of closing
				// and send an ACK packet back to the client
				(*index)->state = sockstate::TIME_WAIT;
				this->sendPacket("IPv4", makePacket(0, *index, htonl(seq + 1),
						TCP_DATA_OFFSET_MIN, TCP_ACK, htons(TCP_WINDOW_SIZE), nullptr));

				// in the TIME_WAIT state, wait for the timeout of 2 MSL, then truly close the socket
				auto payload = new std::pair<std::vector<record *>::iterator, std::vector<record *>::iterator>(index, parentindex);
				this->addTimer(payload, TCP_MSL * 2);
			}

			break;
		case sockstate::LAST_ACK:
			// this is when the server's child socket receives the last signal for closing the connection
			if(!finflag && ackflag && ack == (*index)->nextseq){
				// valid signal, so close the socket, remove the socket record, and wake up the close() call
				this->removeFileDescriptor((*index)->pid, (*index)->sock);
				UUID uuid = (*index)->uuid;
				eraseFromRecords(index, parentindex);

				// no errors
				this->returnSystemCall(uuid, 0);
			}

			break;
		case sockstate::CLOSING:
			// this is when the peer has sent the last response for simultaneous close
			if(!finflag && ackflag && ack == (*index)->nextseq){
				// valid response, so update the socket record for the last stage of closing
				(*index)->state = sockstate::TIME_WAIT;

				// in the TIME_WAIT state, wait for the timeout of 2 MSL, then truly close the socket
				auto payload = new std::pair<std::vector<record *>::iterator, std::vector<record *>::iterator>(index, parentindex);
				this->addTimer(payload, TCP_MSL * 2);
			}

			break;
		case sockstate::TIME_WAIT:
			// no packets to deal with in this state (up to Project 3)
			break;
		default:
			break;
	}

	if(data != nullptr){
		free(data);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	// TIME_WAIT state has timed out, so close the socket, remove the socket record, and wake up the close() call
	auto indexes = (std::pair<std::vector<record *>::iterator, std::vector<record *>::iterator> *)payload;
	this->removeFileDescriptor((*indexes->first)->pid, (*indexes->first)->sock);
	UUID uuid = (*indexes->first)->uuid;
	eraseFromRecords(indexes->first, indexes->second);

	// free memory
	delete indexes;

	// no errors
	this->returnSystemCall(uuid, 0);
}
}
