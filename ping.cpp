/*
    File: ping.cpp
    Author: Christopher Holder
    Ping utlity program.

    Some style notes:
        - I purposely abstained from using exceptions. As I sometimes think that these bring unnecessary complexities.
        -
*/

//STD
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <tuple>

//BOOST
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

//CONSTANTS
#define BUFFER_SIZE_64KB 65536
#define TTL_DEFAULT 64
#define ICMP_HDR_SIZE 8
#define LINUX_PAYLOAD_SIZE 56
#define TIME_BYTE_SIZE 4
#define FILL_BYTE 0X8

template <typename T, typename flag_type = int>
using flagged = std::tuple<flag_type, T>;
using namespace boost::asio;

typedef boost::system::error_code error_code;
typedef unsigned char byte;

enum ICMP : uint8_t {
    ECHO_REPLY = 0,
    UNREACH = 3,
    TIME_EXCEEDED = 11,
    ECHO_REQUEST = 8
};

enum class IPtype {IPV4, IPV6, BOTH};

struct icmp_header_t {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq_num;
};
struct ip_header_t {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t   src_addr;
    uint32_t   dst_addr;
};

ip_header_t ip_load(std::istream& stream, bool ntoh ) {
    ip_header_t header;
    stream.read((char*)&header.ver_ihl,      sizeof(header.ver_ihl));
    stream.read((char*)&header.tos,          sizeof(header.tos));
    stream.read((char*)&header.total_length, sizeof(header.total_length));
    stream.read((char*)&header.id,           sizeof(header.id));
    stream.read((char*)&header.flags_fo,     sizeof(header.flags_fo));
    stream.read((char*)&header.ttl,          sizeof(header.ttl));
    stream.read((char*)&header.protocol,     sizeof(header.protocol));
    stream.read((char*)&header.checksum,     sizeof(header.checksum));
    stream.read((char*)&header.src_addr,     sizeof(header.src_addr));
    stream.read((char*)&header.dst_addr,     sizeof(header.dst_addr));
    if (ntoh) {
      header.total_length = ntohs(header.total_length);
      header.id =           ntohs(header.id);
      header.flags_fo =     ntohs(header.flags_fo);
      header.checksum =     ntohs(header.checksum);
      header.src_addr =     ntohl(header.src_addr);
      header.dst_addr =     ntohl(header.dst_addr);
    }
    return header;
}
icmp_header_t icmp_load(std::istream& stream) {
    icmp_header_t header;
    stream.read((char*)&header.type,      sizeof(header.type));
    stream.read((char*)&header.code,          sizeof(header.code));
    stream.read((char*)&header.checksum, sizeof(header.checksum));
    stream.read((char*)&header.id,           sizeof(header.id));
    stream.read((char*)&header.seq_num,     sizeof(header.seq_num));
    return header;

}

flagged<ip::icmp::endpoint> sync_icmp_solver(io_service& ios, std::string host, 
                                    IPtype type = IPtype::BOTH) noexcept {

    ip::icmp::resolver::query query(host, "");
    ip::icmp::resolver resl(ios);
    ip::icmp::endpoint ep;
    error_code ec;  
    auto it = resl.resolve(query, ec);
    if (ec != 0) {
        std::cerr << "Error message = " << ec.message() << std::endl;
        return std::make_tuple(ec.value(), ep);
    }
    
    ip::icmp::resolver::iterator it_end;
    //Finds first available ip.
    while (it != it_end) {
        ip::icmp::endpoint ep = (it++)->endpoint();
        auto addr = ep.address();
        switch(type) {
            case IPtype::IPV4:
                if (addr.is_v4()) return std::make_tuple(0, ep);
                break;
            case IPtype::IPV6:
                if(addr.is_v6()) return std::make_tuple(0, ep);
                break;
            case IPtype::BOTH:
                return std::make_tuple(0, ep);
                break;
        }
    }
    return std::make_tuple(-1, ep);
}
 
unsigned short checksum(void *b, int len) {   
    unsigned short* buf = reinterpret_cast<unsigned short*>(b); 
    unsigned int sum = 0; 
    unsigned short result; 
  
    for (sum = 0; len > 1; len -= 2 ) {
        sum += *buf++;
    }
         
    if (len == 1) sum += *(byte*) buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 
unsigned short get_identifier() {
#if defined(BOOST_WINDOWS)
    return static_cast<unsigned short>(::GetCurrentProcessId());
#else
    return static_cast<unsigned short>(::getpid());
#endif
  }
struct PingInfo {
    unsigned short seq_num = 0;
    size_t time_out;
    size_t reply_time = 1;
    size_t payload_size = LINUX_PAYLOAD_SIZE; 
    size_t packets_rec = 0; 
    size_t packets_trs = 0;
    size_t reps = 0;
};
class PingConnection {
    private:
        ip::icmp::socket sock;

        io_service* ios_ptr;
        PingInfo* pi_ptr;

        ip::icmp::endpoint dst;
        boost::posix_time::ptime timestamp;
        streambuf input_buf;
        deadline_timer deadtime;
    
        //TODO: Check for memleaks.
        void write_icmp_req(std::ostream& os) {
            byte* pckt = new byte[ICMP_HDR_SIZE + pi_ptr->payload_size];
            unsigned short pid = get_identifier();
            pckt[0] = 0x8;
            pckt[1] = 0x0;
            pckt[2] = 0x0;
            pckt[3] = 0x0;
            pckt[4] = (byte)((pid & 0xF0) >> 4);
            pckt[5] = (byte)(pid & 0x0F);
            for (size_t i = ICMP_HDR_SIZE; i < ICMP_HDR_SIZE + pi_ptr->payload_size; i++) {
                pckt[i] = FILL_BYTE;
            }
            pckt[6] = (byte)((pi_ptr->seq_num & 0xF0) >> 4);
            pckt[7] = (byte)((pi_ptr->seq_num)++ & 0x0F);
            unsigned short cs = checksum(pckt, ICMP_HDR_SIZE);
            pckt[2] = (byte)((cs & 0xF0) >> 4);
            pckt[3] = (byte)(cs & 0x0F);
            os << pckt;
            //delete [] pckt;
        }
        void pckt_send() {
            streambuf buf;
            std::ostream os(&buf);
            write_icmp_req(os);
            timestamp = boost::posix_time::microsec_clock::universal_time();
            sock.send(buf.data());
            deadtime.expires_at(timestamp + boost::posix_time::seconds(pi_ptr->time_out));
            deadtime.async_wait(std::bind(&PingConnection::req_timeout_callback, this));
        }
        void req_timeout_callback() {
            if (pi_ptr->reps == 0) {
                std::cout << "Time Out:echo req" << std::endl;
            }
            deadtime.expires_at(timestamp + boost::posix_time::seconds(pi_ptr->reply_time));
            deadtime.async_wait(std::bind(&PingConnection::pckt_send, this));
        }
        void pckt_recv() {
            input_buf.consume(input_buf.size());
            sock.async_receive(input_buf.prepare(BUFFER_SIZE_64KB),
            std::bind(&PingConnection::recv_timeout_callback, this, std::placeholders::_2));
        }
        void recv_timeout_callback(size_t sz) {
            input_buf.commit(sz);
            std::istream is(&input_buf);
            ip_header_t iph = ip_load(is, false);
            icmp_header_t icmph = icmp_load(is);
            if (is && 
                icmph.type == ECHO_REQUEST && 
                icmph.id == get_identifier() && 
                icmph.seq_num == pi_ptr->seq_num) {
                
            // If this is the first reply, interrupt the five second timeout.
            if (pi_ptr->reps++ == 0) deadtime.cancel();

            boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
            std::cout << sz - iph.total_length
                        << " bytes from " << iph.src_addr
                        << ": icmp_seq=" << icmph.seq_num
                        << ", ttl=" << iph.ttl
                        << ", time=" << (now - timestamp).total_milliseconds() << " ms"
                        << std::endl;
            }

            pckt_recv();
        }
        
    public:
        PingConnection(io_service& ios, PingInfo& pi_add) : deadtime(ios), sock(ios) {
            pi_ptr = &pi_add;
            ios_ptr = &ios;
        }
        void ping(std::string host) {
            int err_flag;
            std::tie(err_flag, dst) = sync_icmp_solver(*ios_ptr, "google.com");
            if (err_flag) return;
            std::cout << dst << std::endl;
            sock.connect(dst);
            pckt_send();
            pckt_recv();
        }
        
};


int main(int argc, char** argv) {
    
    if (argc < 2) {
         std::cerr << "Usage: ping [args]* destination\n";
         return -1;
    }
    io_service ios;
    PingInfo pi;
    pi.time_out = 56;
    PingConnection ping(ios, pi);
    ping.ping(argv[1]);
    ios.run();

}