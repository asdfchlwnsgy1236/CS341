/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 *
 * Modified on: 20181001
 * asdfchlwnsgy1236
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <E/E_TimerModule.hpp>

#include <cstring>
#include <string>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	virtual void syscall_socket(UUID uuid, int pid, int param1, int param2);
	virtual void syscall_close(UUID uuid, int pid, int param1);
	virtual void syscall_bind(UUID uuid, int pid, int param1, struct sockaddr *param2, int param3);
	virtual void syscall_getsockname(UUID uuid, int pid, int param1, struct sockaddr *param2, socklen_t *param3);

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}

#endif /* E_TCPASSIGNMENT_HPP_ */
