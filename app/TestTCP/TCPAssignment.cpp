/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 *
 * Modified on: 20181001
 * asdfchlwnsgy1236
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
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

// the struct for recording a bound socket and its information
struct record{
	int sock;
	struct sockaddr_in addr;
};

// the list of bound sockets 
std::list<struct record> bindrecs;

// system call socket
void TCPAssignment::syscall_socket(UUID uuid, int pid, int param1, int param2){
	// create a file descriptor and use the system's return call to pass it on
	this->returnSystemCall(uuid, this->createFileDescriptor(pid));
}

// system call close
void TCPAssignment::syscall_close(UUID uuid, int pid, int param1){
	// go through the list of bound sockets and if the socket to be closed is found, remove it
	for(auto a = bindrecs.begin(); a != bindrecs.end(); a++){
		if((*a).sock == param1){
			bindrecs.erase(a);
			break;
		}
	}
	// regardless of whether the socket was found in the list or not, close it
	this->removeFileDescriptor(pid, param1);

	// indicate that no errors occurred
	this->returnSystemCall(uuid, 0);
}

// system call bind
void TCPAssignment::syscall_bind(UUID uuid, int pid, int param1, struct sockaddr *param2, int param3){
	struct sockaddr_in *addr = (struct sockaddr_in *)param2;
	unsigned long anyaddr = htonl(INADDR_ANY);

	// check if there are any conflicts between the existing bound sockets and the to-be-bound socket according to the rules
	for(auto a: bindrecs){
		if(a.sock == param1 || a.addr.sin_port == addr->sin_port &&
				(a.addr.sin_addr.s_addr == addr->sin_addr.s_addr ||
				a.addr.sin_addr.s_addr == anyaddr || addr->sin_addr.s_addr == anyaddr)){
			// indicate that an error occurred
			this->returnSystemCall(uuid, -1);
			return;
		}
	}

	// there are no conflicts, so add the to-be-bound socket to the bound sockets list
	struct record toadd;
	std::memset(&toadd, 0, sizeof(toadd));
	toadd.sock = param1;
	toadd.addr.sin_family = addr->sin_family;
	toadd.addr.sin_port = addr->sin_port;
	toadd.addr.sin_addr.s_addr = addr->sin_addr.s_addr;
	bindrecs.push_back(toadd);

	// indicate that no errors occurred
	this->returnSystemCall(uuid, 0);
}

// system call getsockname
void TCPAssignment::syscall_getsockname(UUID uuid, int pid, int param1, struct sockaddr *param2, socklen_t *param3){
	// search for the socket in question and if found, fill the provided address structure with the address data and set the length
	for(auto a: bindrecs){
		if(a.sock == param1){
			*param3 = sizeof(a.addr) < *param3 ? sizeof(a.addr) : *param3;
			std::memcpy(param2, &(a.addr), *param3);
			// indicate that no errors occurred
			this->returnSystemCall(uuid, 0);
			return;
		}
	}

	// indicate that an error occurred
	this->returnSystemCall(uuid, -1);
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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
