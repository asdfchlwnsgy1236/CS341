/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 *
 * Project 2 completed: 20181001
 * Project 3 modified: 20181030
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

#include <string>
#include <utility>

namespace E
{
// enumerator for socket states
enum class sockstate{
	CLOSED = 0,
	LISTEN,
	SYN_SENT,
	SYN_RCVD,
	ESTABLISHED,
	FIN_WAIT_1,
	CLOSE_WAIT,
	FIN_WAIT_2,
	LAST_ACK,
	CLOSING,
	TIME_WAIT
};

// enumerator for the socket record's invector field
enum class sockinvec{
	IN_BINDRECS = 0,
	IN_PENDING,
	IN_ESTABLISHED,
	IN_ACCEPTED
};

// the struct for recording a bound socket and relevant information
struct record{
	// the UUID for waking up connect and accept calls
	UUID uuid;
	// the pid of the process that made this socket record
	int pid;
	// the socket file descriptor
	int sock;
	// the backlog value for the server only
	unsigned int backlog;
	// the sequence number and expected acknowledgment number / next sequence number used when sending and receiving packets
	unsigned int seq, nextseq;
	// the state of the socket according to the state diagram
	sockstate state;
	// the source and destination address structures for this socket
	sockaddr_in addr, otheraddr;
	// the address structure that the accept function must fill before returning
	sockaddr *acceptaddr;
	// the address structure size variable that the accept function must modify before returning
	socklen_t *acceptaddrsize;
	// the pending, established, and accepted connections lists for the server only
	std::vector<record *> pending, established, accepted;
	// indicator for whether the socket is in bindrecs, pending, established, or accepted for use in closing
	sockinvec invector;
	// indicator for whether the socket is sleeping (e.g. blocked by connect / accept calls)
	// as well as for whether the UUID is valid
	bool sleeping;

	// normal constructor
	record(UUID uuid, int pid, int sock, unsigned int backlog, unsigned int seq, unsigned int nextseq, sockstate state,
			unsigned int srcaddr, unsigned short srcport, unsigned int dstaddr, unsigned short dstport,
			sockinvec invector, bool sleeping);
	// default constructor
	record();
	// copy constructor
	record(record const &r);
	// move constructor
	record(record &&r);
	// default destructor
	~record() = default;
	// copy assignment operator
	record &operator=(record const &r);
	// move assignment operator
	record &operator=(record &&r);
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	virtual void timerCallback(void* payload) final;

	// the list of bound sockets
	std::vector<record *> bindrecs;
	// the "random" sequence number to use
	unsigned int randomseq;
	// the "random" port number to use
	unsigned short randomport;

	// helper function that finds the matching socket record for the given pid and socket
	std::vector<record *>::iterator findInRecords(int pid, int sock);
	// helper function that compares the record and the addresses and ports to see if they match
	bool recordMatchesAddrs(std::vector<record *>::iterator index, unsigned int anyaddr,
			unsigned int srcaddr, unsigned short srcport,
			unsigned int dstaddr, unsigned short dstport);
	// helper function that finds the matching bound socket, pending connection, established connection,
	// or accepted connection record for the given source and destination addresses and ports
	std::vector<record *>::iterator findInRecords(unsigned int srcaddr, unsigned short srcport,
			unsigned int dstaddr, unsigned short dstport);
	// helper function that finds the matching socket record for the given address and port
	std::vector<record *>::iterator findInRecords(unsigned int srcaddr, unsigned short srcport);
	// helper function that calculates the checksum of the given packet
	unsigned short calculateChecksum(Packet *packet);
	// helper function that makes a packet
	Packet *makePacket(size_t datasize, record const *rec, unsigned int ack,
			unsigned char dataoffset, unsigned char flags, unsigned short windowsize, void *data);
	// helper function that erases the given socket record properly depending on which vector it is in
	void eraseFromRecords(std::vector<record *>::iterator index, std::vector<record *>::iterator parentindex);
	// debug function that prints out the content of a struct record
	void printRecord(record const *rec);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

	virtual void syscall_socket(UUID uuid, int pid, int param1, int param2);
	virtual void syscall_close(UUID uuid, int pid, int param1);
//	virtual void syscall_read(UUID uuid, int pid, int param1, void *param2, int param3);
//	virtual void syscall_write(UUID uuid, int pid, int param1, void *param2, int param3);
	virtual void syscall_connect(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t param3);
	virtual void syscall_listen(UUID uuid, int pid, int param1, int param2);
	virtual void syscall_accept(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3);
	virtual void syscall_bind(UUID uuid, int pid, int param1, sockaddr *param2, int param3);
	virtual void syscall_getsockname(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3);
	virtual void syscall_getpeername(UUID uuid, int pid, int param1, sockaddr *param2, socklen_t *param3);

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
