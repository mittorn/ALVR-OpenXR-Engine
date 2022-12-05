#define _BSD_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "alxr_engine.h"
// v19-
typedef struct [[gnu::packed]] headset_info_s
{
	uint32_t recommended_eye_width;
	uint32_t recommended_eye_height;
	uint64_t available_refresh_rates_len; // 5
	float available_refresh_rates[5];
	float preferred_refresh_rate;
	uint32_t microphone_sample_rate;
	uint64_t reserved_string_len; // 0x1f
	char reserved_string[0x1f];
} headset_info_t;

// v19-
typedef struct [[gnu::packed]] client_connection_result_accepted_s_
{
	uint32_t accepted; //0
	headset_info_t headset_info;
	uint32_t server_ip_ipv; //0
	uint32_t server_ip;
} client_connection_result_accepted_t_;

typedef struct [[gnu::packed]] VideoStreamingCapabilities_s
{
	uint8_t some; // 1 // fucking mouth of rust serde
	uint32_t recommended_eye_width;
	uint32_t recommended_eye_height;
	uint64_t available_refresh_rates_len; // 1 //5
	float available_refresh_rates[1];
	uint32_t microphone_sample_rate;

} VideoStreamingCapabilities_t;

typedef struct [[gnu::packed]] client_connection_result_accepted_s
{
	uint32_t accepted; //0
	uint64_t display_name_len; // 4 //8
	char display_name[8];
	uint32_t server_ip_ipv; // 0
	uint32_t server_ip;
	VideoStreamingCapabilities_t streaming_capabilities;
} client_connection_result_accepted_t;

int read_packet_ldc(int fd, void *buf, size_t maxlen)
{
	uint32_t len, left = 0;
	int ret;
	char trash[2048];
	if(read(fd, (void*)&len, 4) < 0)
		return -1;
	len = htonl(len);
	if(len > maxlen) left = len - maxlen, len = maxlen;
	ret = read(fd, buf, len);
	if(ret != len)
		return ret;
	while(left > 2048)
	{
		read(fd, trash, 2048);
		left -= 2048;
	}
	if(left)
		read(fd,trash,left);
	return ret;
}
int send_packet_ldc(int fd, void *buf, size_t len)
{
	uint32_t sendlen = htonl((uint32_t)len);
	int ret = write(fd, &sendlen, 4);
	if(ret < 4)
		return ret;
	return write(fd, buf, len);
}

// 20.0.0-dev1 fucked up decoder config, disable it to use v19
#define FUCKUP_DECODER_CONFIG 1
enum server_control_packet
{
	StartStream,
#if FUCKUP_DECODER_CONFIG
	InitializeDecoder, // version break
#endif
	Restarting,
	KeepAlive_s,
	SomeString_s,
	SomeBuffer_s
};

enum client_control_packet
{
	PlayspaceSync,
	RequestIdr,
	KeepAlive_c,
	StreamReady,
	ViewsConfig,
	Battery,
	VideoErrorReport, // legacy
	Button,
	ActiveInteractionProfile,
	SomeString_c,
	SomeBuffer_c,
};

typedef struct [[gnu::packed]] views_config_packet_s
{
	uint32_t id; // ViewsConfig
	float ipd_m;
	float fov[8];
} views_config_packet_t;

struct [[gnu::packed]] device_motion_s
{
	uint64_t id;
	float orientation[4];
	float position[3];
	float linear_velocity[3];
	float angular_velocity[3];
};

typedef struct [[gnu::packed]] duration_s
{
	uint64_t secs;
	uint32_t nanos;
}
duration_t;

struct [[gnu::packed]] playerspace
{
	uint32_t id;
	float psp[2];
};

typedef struct [[gnu::packed]] tracking_s
{
	duration_t target_timestamp;
	uint64_t device_motions_len; // 3
	struct device_motion_s device_motions[3];
	uint8_t left_hand_skeleton, right_hand_skeleton;
} tracking_t;

typedef struct [[gnu::packed]] stream_header_s
{
uint16_t channel;
uint32_t frame;
}
stream_header_t;

struct [[gnu::packed]] VideoFrameHeaderPacket
{
	uint32_t packet_counter;
	uint64_t tracking_frame_index;
	uint64_t video_frame_index;
	uint64_t sent_time;
	uint32_t frame_byte_size;
	uint32_t fec_index;
	uint16_t fec_percentage;
};


typedef struct [[gnu::packed]] tracking_packet_s
{
	stream_header_t header;
	tracking_t body;
} tracking_packet_t;

typedef struct [[gnu::packed]] connection_accept_s
{
	char alvr_name[16];
	uint64_t version_hash;
	char hostname[56-24];
} connection_accept_t;

int stream_fd;
#include <pthread.h>

// rust is shit
// ALVR protocol is shit
// is there any reason for making hasher without specified algorithm?
// although it's documented as unstable, someone will rely on it in protocol
// is there any reason to use this hasher in protocol although documentation says not to rely on it?
// but who reads the documentation? it's only dirty paper
// Rust wants to be safe, but does not have fool-proof for such cases
// anyone rewriting something to rust for "safety" must burn in hell, memory safety is not panacea, they are in fake "safety"
// hash values got from debugger because i fauled to find which hasher Rust use for now!

#define USER_HEAD "/user/head"
#define USER_HEAD_HASH 0x5b90853dc9202538
#define USER_HAND_LEFT "/user/hand/left"
#define USER_HAND_LEFT_HASH 0xe521d8dabe2d07a2
#define USER_HAND_RIGHT "/user/hand/right"
#define USER_HAND_RIGHT_HASH 0xf6b81330eb3dbdd8
#define USER_HAND_LEFT_OUTPUT_HAPTIC "/user/hand/left/output/haptic"
#define USER_HAND_LEFT_OUTPUT_HAPTIC_HASH 0x25fd7bfe18f934eb
#define USER_HAND_RIGHT_OUTPUT_HAPTIC "/user/hand/right/output/haptic"
#define USER_HAND_RIGHT_OUTPUT_HAPTIC_HASH 0x47199a1ef16c8d19


#define HANDLE_HASH_(x) x
#define HANDLE_HASH(x) if(!strcmp(path,x))\
							return x##_HASH

unsigned long long path_string_to_hash(const char *path)
{
	HANDLE_HASH(USER_HEAD);
	HANDLE_HASH(USER_HAND_LEFT);
	HANDLE_HASH(USER_HAND_RIGHT);
	HANDLE_HASH(USER_HAND_LEFT_OUTPUT_HAPTIC);
	HANDLE_HASH(USER_HAND_RIGHT_OUTPUT_HAPTIC);
	return 0;
}


struct [[gnu::packed]] video_buf
{
	VideoFrame header;
	char buffer[1024*1024];
};


void* stream_func(void*)
{
	video_buf decode_buffer = {{9}};
	//printf("%d\n", sizeof(client_connection_result_accepted_t));
	int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr;
	inet_aton("127.0.0.1",&addr.sin_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9944); //htons(9943);
	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
	bind(server_fd,(struct sockaddr*)&addr, sizeof(addr));
	listen(server_fd,1);
	int fd;
	struct sockaddr_in client;
	socklen_t clientlen = sizeof(client);
	//client_connection_result_accepted_t hs_answer;
	//int f = open("/mnt/data2/ALVR18/handshake.bin", O_RDONLY);
	//read_packet_ldc(f, (void*)&hs_answer, sizeof(hs_answer));
	//close(f);
	while((fd = accept(server_fd, (sockaddr*)&client, &clientlen)) >= 0)
	{
		char buf[1024*1024*3];
		//send_packet_ldc(fd, &hs_answer, sizeof(hs_answer));
//		int len = read_packet_ldc(fd, &buf, sizeof(buf));
		//write(1, &buf, len);
		uint32_t answ = StreamReady;
		//send_packet_ldc(fd, &answ, 4);
		int len;
		while(1)
		{
		stream_fd = fd;
		len = read_packet_ldc(fd, buf+4, sizeof(buf)-4);
		uint16_t id;
		memcpy(&id,buf+4,2);
		if(htons(id)!= 2)
		fprintf(stdout,"%d %d %lu\n", htons(id), len, *(uint64_t*)&buf[8]);
		if(htons(id) == 3)
		{
			/* frames rearranged by rust sender code somehow, but FEC queue may fix it.
			   video will be broken without enabled fec */
			VideoFrameHeaderPacket *header = (VideoFrameHeaderPacket*)&buf[10];
			printf("v%d %d %d %d\n", header->packet_counter, header->tracking_frame_index, header->frame_byte_size, len - sizeof(VideoFrameHeaderPacket) - 6);
			
			decode_buffer.header.packetCounter = header->packet_counter;//((VideoFrameHeaderPacket*)&buf[6])->packet_counter;
			decode_buffer.header.trackingFrameIndex = header->tracking_frame_index;
			decode_buffer.header.videoFrameIndex = header->video_frame_index;
			decode_buffer.header.sentTime = header->sent_time;
			decode_buffer.header.frameByteSize = header->frame_byte_size;
			decode_buffer.header.fecIndex = header->fec_index;
			decode_buffer.header.fecPercentage = header->fec_percentage;
			/// TODO: rework layout to skip this copy
			memcpy((void*)&decode_buffer.buffer,(void*)(&buf[10] + sizeof(VideoFrameHeaderPacket)), len - sizeof(VideoFrameHeaderPacket) - 6);


//			*((int*)&buf[0]) = 9;
//			*((int*)&buf[4]) = counter;
			alxr_on_receive((unsigned char*)&decode_buffer, len - sizeof(VideoFrameHeaderPacket) - 6 + sizeof(VideoFrame));
		}
		
//		tracking_packet_t tracking = {0};
//		tracking.header.channel = 0;
//		tracking.body.device_motions_len = 3;
//		memcpy(tracking.body.device_motions[0].orientation, ptr->HeadPose_Pose_Orientation
//		send_packet_ldc(fd, &tracking, sizeof(tracking));
		//if(htons(id) == 2)
//			write(1, ((char*)buf)+6, len-6);
		}
		sleep(10);
		close(fd);
	}
	return 0;
}

static pthread_mutex_t stream_write_lock;
static pthread_mutex_t control_write_lock;
int control_fd;


void request_idr()
{
	printf("IDR req\n");
}

void set_waiting_next_idr(bool waiting)
{
	printf("IDR waiting %d\n",(int)waiting);

}

void video_error_report_send()
{
}

void time_sync_send(const TimeSync *data)
{
}

void battery_send(unsigned long long id, float value, bool plugged)
{
}

void views_config_send(const ALXREyeInfo *eye)
{
	views_config_packet_t vconfig = {
	ViewsConfig,
	eye->ipd,
	eye->eyeFov[0].left,
	eye->eyeFov[0].right,
	-eye->eyeFov[0].bottom,
	-eye->eyeFov[0].top,
	eye->eyeFov[1].left,
	eye->eyeFov[1].right,
	-eye->eyeFov[1].bottom,
	-eye->eyeFov[1].top,
	};
	send_packet_ldc(control_fd, &vconfig, sizeof(vconfig));
}

void input_send(const TrackingInfo *ptr)
{
	static int frame = 0;
	tracking_packet_t tracking = {0};
	tracking.header.channel = 0;
	tracking.header.frame = frame++;
	tracking.body.target_timestamp.secs = ptr->targetTimestampNs / (unsigned long long)1e9;
	tracking.body.target_timestamp.nanos = ptr->targetTimestampNs % (unsigned long long)1e9;
	tracking.body.device_motions_len = 3;
	tracking.body.device_motions[0].id = USER_HEAD_HASH;
	memcpy(tracking.body.device_motions[0].orientation, &ptr->HeadPose_Pose_Orientation, 4*4);
	memcpy(tracking.body.device_motions[0].position, &ptr->HeadPose_Pose_Position, 4*3);
	send_packet_ldc(stream_fd, &tracking, sizeof(tracking));
}

static ALXRRustCtx ctx = 
{
input_send,
views_config_send,
path_string_to_hash,
time_sync_send,
video_error_report_send,
battery_send,
set_waiting_next_idr,
request_idr,
Vulkan,
VAAPI,
Rec2020,
false,
false,
false,
false,
false,
false
};
static float rates[] = {60, 72, 80, 90, 120};
static ALXRSystemProperties props = 
{
"Linux unSafeXR",
60,
rates,
1,
1007,
896
};

struct [[gnu::packed]] ClientConfigFooter
{
uint32_t eye_resolution_x;
uint32_t eye_resolution_y;
float fps;
uint32_t game_audio_sample_rate;
};


static ALXRStreamConfig stream_config = {
StageRefSpace,
{
	0,
	0,
	0,
	0.4,
	0.35,
	0.4,
	0.1,
	4,
	5,
	true
},
{
HEVC_CODEC,
true, // fec
false,
1
}
};

void init_engine()
{
	alxr_init(&ctx, &props);
}

void *control_func(void*)
{
	video_buf buf = {{9}};
	char buffer[1024*1024];
	bool initialized = false;
	while(true)
	{
		size_t len = read_packet_ldc(control_fd, &buffer[0], sizeof(buffer));
		printf("Control packed %d %d\n", *(unsigned int*)(&buffer[0]), (int)len - 4);
		if(*(unsigned int*)(&buffer[0]) == KeepAlive_s)
		{
			int answ = RequestIdr;
//			send_packet_ldc(control_fd, &answ, 4);
		}
#if FUCKUP_DECODER_CONFIG
		if(*(unsigned int*)(&buffer[0]) == InitializeDecoder)
		{
			printf("Decoder init!\n");
			buf.header.fecIndex = 0;
			buf.header.fecPercentage = 0;
			buf.header.frameByteSize = len - 4;
			memcpy(buf.buffer, buffer+4, len - 4);

			if(!initialized)
				alxr_on_receive((unsigned char*)&buf,sizeof(VideoFrame) + len - 4);
			initialized = true;
		}
#endif
	}

}

int main()
{
	//printf("%d\n", sizeof(client_connection_result_accepted_t));
	int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr;
	inet_aton("127.0.0.1",&addr.sin_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9943); //htons(9943);
	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
	bind(server_fd,(struct sockaddr*)&addr, sizeof(addr));
	listen(server_fd,1);
	int fd;
	struct sockaddr_in client;
	socklen_t clientlen = sizeof(client);
	client_connection_result_accepted_t hs_answer = {0, 8, {'u','n','S','a','f','e','X','R'}, 0, 0x0100007f, {1, 1007, 896, 1, {60}, 48000}};
	pthread_t stream_thread;
	pthread_create(&stream_thread, NULL, &stream_func, 0);
	sleep(1);
///	int f = open("/mnt/data2/ALVR18/handshake.bin", O_RDONLY);
///	read_packet_ldc(f, (void*)&hs_answer, sizeof(hs_answer));
///	close(f);
	connection_accept_t ann = { "ALVR", 18166762639281986762U, "x.client.alvr"};
	init_engine();
	
	while((fd = accept(server_fd, (struct sockaddr*)&client, &clientlen)) >= 0)
	{
		char buf[8192];
		//send_packet_ldc(fd, &ann, sizeof(ann));
		send_packet_ldc(fd, &hs_answer, sizeof(hs_answer));
		int len = read_packet_ldc(fd, &buf, sizeof(buf));
		printf("%d\n", *(int*)&buf);
		//write(1, &buf, len);
		ClientConfigFooter *config = (ClientConfigFooter*)&buf[len - sizeof(ClientConfigFooter)];
		stream_config.renderConfig.refreshRate = config->fps;
		stream_config.renderConfig.eyeWidth = config->eye_resolution_x;
		stream_config.renderConfig.eyeHeight = config->eye_resolution_y;
		
		uint32_t answ = StreamReady;
		send_packet_ldc(fd, &answ, 4);
		len = read_packet_ldc(fd, &buf, sizeof(buf));
		//write(1, &buf, len);
		//views_config_packet_t vconfig = {ViewsConfig};
//		vconfig.id = ViewsConfig;
		//send_packet_ldc(fd, &vconfig, sizeof(vconfig));
		answ = RequestIdr;
		send_packet_ldc(fd, &answ, 4);
		//sleep(60);
		
		control_fd = fd;
		pthread_t control_thread;
		pthread_create(&control_thread,0,control_func,0);
		alxr_set_stream_config(stream_config);
		bool stop = false;
		while(!stop)
		{
			bool restart = false;
			alxr_process_frame(&stop, &restart);
			alxr_on_tracking_update(false);
//			usleep(16);
		}
		alxr_destroy();
		close(fd);
	}
	return 0;
}

