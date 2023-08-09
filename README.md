# O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator

## Setup
- `pip install --user pipenv`
- `pipenv install streamlit`
  - If error, `pip3 uninstall virtualenv`
- `pipenv install spacy`
- `pipenv install ntlk`
- `pipenv install IPython`
- `pipenv install openai`
- copy the `.env.template` file and rename to `.env`, apply for OpenAI API key and add the OpenAI API key to `OPENAI_API_KEY`

## Run
- `pipenv shell`
- `streamlit run app.py`

## Tests
### Example Use Case Scenario Title
`Transmitting Messages via RMR Transmission Medium`
### Example Use Case Scenario
```
Given a dialer xApp and a listener xApp
And dialer xApp connected to RMR transmission medium successfully
And listener xApp connected to RMR transmission medium successfully
When dialer xApp sends a message to the listener xApp via RMR transmission medium
Then the listener xApp receive the message
```

### Example Use Case Scenario Title
`Newly registered and subscribed xApp to access resources from target xApp`
### Example Use Case Scenario
```
Given a new xApp registers with the Near-RT RIC
And the new xApp subscribe to the desired RAN stacks through the E2 termination in the near-RT RICs and the E2 agents on the RAN nodes
And a target xApp is already registered with the Near-RT RIC
And the target xApp subscribed to the desired RAN stacks through the E2 termination in the near-RT RICs and the E2 agents on the RAN nodes
When the new xApp wants to access resources from target xApp
Then target xApp responds with its resources to the new xApp
```

```
Given a new xApp registers with the Near-RT RIC without authentication and authorization
And the new xApp subscribe to the desired RAN stacks through the E2 termination in the near-RT RICs and the E2 agents on the RAN nodes
And a target xApp is already registered with the Near-RT RIC without authentication and authorization
And the target xApp subscribed to the desired RAN stacks through the E2 termination in the near-RT RICs and the E2 agents on the RAN nodes
When the new xApp wants to access resources from target xApp via RMR transmission medium without authentication and authorization 
Then target xApp responds with its resources to the new xApp
```

### Example Use Case Scenario Title
`Login`
### Example Use Case Scenario
```
Given these users have been created with default attributes and without skeleton files
When user Alice logs in using the webUI
Then the user should be redirected to a webUI page with the title Files-%productname%
```

### Example Use Case Scenario Title
`Change Email Address`
### Example Use Case Scenario
```
Given user Alice has been created with default attributes and without skeleton files
And user Alice has logged in use the webUI
And the user has browsed to the personal general settings page
When the user changes the email address to new-address@owncloud.com user the webUI
And the user follows the email change confirmation link received by new-address@owncloud.com using the webUI
Then the attributes of user Alice returned by the API should include | email | new-address@owncloud.com
```

## Prompt design to generate tags for capec.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with CAPEC and want to use CAPEC to match with potential threats. 

Here is the CAPEC title,
<input CAPEC id>: <input CAPEC title>

Here is the CAPEC description,
<input CAPEC description>

Here are the mitigations of CAPEC,
<input mitigations>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```

## Prompt design to generate tags for oran-components.json and oran-near-rt-ric.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with O-RAN Alliance Security Work Group. Also, you are familiar with the O-RAN Security Threat Modeling and Remediation Analysis document. You want to use the O-RAN Security Threat Modeling and Remediation Analysis document to match with potential threats. 

Here is the O-RAN Security Threat Modeling and Remediation Analysis threat title,
<input threat title>

Here is the O-RAN Security Threat Modeling and Remediation Analysis threat description,
<input threat description>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```

## Prompt design to generate tags for oran-security-analysis.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with O-RAN Alliance Security Work Group. Also, you are familiar with the Study on Security for Near Real Time RIC and xApps. You want to use the Study on Security for Near Real Time RIC and xApps document to match with potential threats. 

Here is the issue title,
<input issue title>

Here is the issue detail,
<input issue detail>

Here are the security threats as an array of strings,
<input security threats as an array of strings>

Here are the security requirements as an array of strings,
<input security requirements as an array of strings>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```

## Application Source Code tested
### Sender
```C
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>

#include <rmr/rmr.h>

int main( int argc, char** argv ) {
	void* mrc;      						//msg router context
	struct epoll_event events[1];			// list of events to give to epoll
	struct epoll_event epe;                 // event definition for event to listen to
	int     ep_fd = -1;						// epoll's file des (given to epoll_wait)
	int rcv_fd;     						// file des that NNG tickles -- give this to epoll to listen on
	int nready;								// number of events ready for receive
	rmr_mbuf_t*		sbuf;					// send buffer
	rmr_mbuf_t*		rbuf;					// received buffer
	int	count = 0;
	int	rcvd_count = 0;
	char*	listen_port = "43086";
	int		delay = 1000000;						// mu-sec delay between messages
	int		mtype = 0;
	int		stats_freq = 100;

	if( argc > 1 ) {
		listen_port = argv[1];
	}
	if( argc > 2 ) {
		delay = atoi( argv[2] );
	}
	if( argc > 3 ) {
		mtype = atoi( argv[3] );
	}

	fprintf( stderr, "<DEMO> listen port: %s; mtype: %d; delay: %d\n", listen_port, mtype, delay );

	if( (mrc = rmr_init( listen_port, 1400, RMRFL_NONE )) == NULL ) {
		fprintf( stderr, "<DEMO> unable to initialise RMr\n" );
		exit( 1 );
	}

	rcv_fd = rmr_get_rcvfd( mrc );					// set up epoll things, start by getting the FD from MRr
	if( rcv_fd < 0 ) {
		fprintf( stderr, "<DEMO> unable to set up polling fd\n" );
		exit( 1 );
	}
	if( (ep_fd = epoll_create1( 0 )) < 0 ) {
		fprintf( stderr, "[FAIL] unable to create epoll fd: %d\n", errno );
		exit( 1 );
	}
	epe.events = EPOLLIN;
	epe.data.fd = rcv_fd;

	if( epoll_ctl( ep_fd, EPOLL_CTL_ADD, rcv_fd, &epe ) != 0 )  {
		fprintf( stderr, "[FAIL] epoll_ctl status not 0 : %s\n", strerror( errno ) );
		exit( 1 );
	}

	sbuf = rmr_alloc_msg( mrc, 256 );	// alloc first send buffer; subsequent buffers allcoated on send
	rbuf = NULL;						// don't need to alloc receive buffer

	while( ! rmr_ready( mrc ) ) {		// must have a route table before we can send; wait til RMr say it has one
		sleep( 1 );
	}
	fprintf( stderr, "<DEMO> rmr is ready\n" );
	

	while( 1 ) {										// send messages until the cows come home
		snprintf( sbuf->payload, 200, "count=%d received= %d ts=%lld %d stand up and cheer!", 	// create the payload
			count, rcvd_count, (long long) time( NULL ), rand() );

		sbuf->mtype = mtype;							// fill in the message bits
		sbuf->len =  strlen( sbuf->payload ) + 1;		// our receiver likely wants a nice acsii-z string
		sbuf->state = 0;
		sbuf->sub_id = -1;
		sbuf = rmr_send_msg( mrc, sbuf );				// send it (send returns an empty payload on success, or the original payload on fail/retry)
		fprintf( stderr, "sbuf->state %d\n", sbuf->state );
		while( sbuf->state == RMR_ERR_RETRY ) {			// soft failure (device busy?) retry
			sbuf = rmr_send_msg( mrc, sbuf );			// retry send until it's good (simple test; real programmes should do better)
		}

		if ( sbuf->state == RMR_OK ) {
			fprintf( stderr, "<DEMO> rmr ok\n" );
		}

		count++;

		while( (nready = epoll_wait( ep_fd, events, 1, 0 )) > 0 ) {	// if something ready to receive (non-blocking check)
			if( events[0].data.fd == rcv_fd ) {             // we only are waiting on 1 thing, so [0] is ok
				errno = 0;
				rbuf = rmr_rcv_msg( mrc, rbuf );
				if( rbuf ) {
					rcvd_count++;
				}
			}
		}

		if( (count % stats_freq) == 0 ) {
			fprintf( stderr, "<DEMO> sent %d   received %d\n", count, rcvd_count );
		}

		usleep( delay );
	}
}
```

### Receiver
```C
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <rmr/rmr.h>


int main( int argc, char** argv ) {
	void* mrc;      					// msg router context
	long long total = 0;
	rmr_mbuf_t* msg = NULL;				// message received
	int stat_freq = 10;				// write stats after reciving this many messages
	int i;
	char*	listen_port = "4560";		// default to what has become the standard RMR port
	long long count = 0;
	long long bad = 0;
	long long empty = 0;

	if( argc > 1 ) {
		listen_port = argv[1];
	}
	if( argc > 2 ) {
		stat_freq = atoi( argv[2] );
	}
	fprintf( stderr, "<DEMO> listening on port: %s\n", listen_port );
	fprintf( stderr, "<DEMO> stats will be reported every %d messages\n", stat_freq );

	mrc = rmr_init( listen_port, RMR_MAX_RCV_BYTES, RMRFL_NONE );	// start your engines!
	if( mrc == NULL ) {
		fprintf( stderr, "<DEMO> ABORT:  unable to initialise RMr\n" );
		exit( 1 );
	}

	while( ! rmr_ready( mrc ) ) {								// wait for RMr to load a route table
		fprintf( stderr, "<DEMO> waiting for ready\n" );
		sleep( 3 );
	}
	fprintf( stderr, "<DEMO> rmr now shows ready\n" );

	while( 1 ) {											// forever; ctl-c, kill -15, etc to end
		msg = rmr_rcv_msg( mrc, msg );						// block until one arrives
		
		if( msg ) {
			if( msg->state == RMR_OK ) {
				count++;									// messages received for stats output
			} else {
				bad++;
			}
		} else {
			empty++;
		}

		if( (count % stat_freq) == 0  ) {
			fprintf( stderr, "<DEMO> total msg received: %lld  errors: %lld   empty: %lld\n", count, bad, empty );
		}

	}
}
```

### Application Code
```
xApp Sender application source code:
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>

#include <rmr/rmr.h>

int main( int argc, char** argv ) {
	void* mrc;      						//msg router context
	struct epoll_event events[1];			// list of events to give to epoll
	struct epoll_event epe;                 // event definition for event to listen to
	int     ep_fd = -1;						// epoll's file des (given to epoll_wait)
	int rcv_fd;     						// file des that NNG tickles -- give this to epoll to listen on
	int nready;								// number of events ready for receive
	rmr_mbuf_t*		sbuf;					// send buffer
	rmr_mbuf_t*		rbuf;					// received buffer
	int	count = 0;
	int	rcvd_count = 0;
	char*	listen_port = "43086";
	int		delay = 1000000;						// mu-sec delay between messages
	int		mtype = 0;
	int		stats_freq = 100;

	if( argc > 1 ) {
		listen_port = argv[1];
	}
	if( argc > 2 ) {
		delay = atoi( argv[2] );
	}
	if( argc > 3 ) {
		mtype = atoi( argv[3] );
	}

	fprintf( stderr, "<DEMO> listen port: %s; mtype: %d; delay: %d\n", listen_port, mtype, delay );

	if( (mrc = rmr_init( listen_port, 1400, RMRFL_NONE )) == NULL ) {
		fprintf( stderr, "<DEMO> unable to initialise RMr\n" );
		exit( 1 );
	}

	rcv_fd = rmr_get_rcvfd( mrc );					// set up epoll things, start by getting the FD from MRr
	if( rcv_fd < 0 ) {
		fprintf( stderr, "<DEMO> unable to set up polling fd\n" );
		exit( 1 );
	}
	if( (ep_fd = epoll_create1( 0 )) < 0 ) {
		fprintf( stderr, "[FAIL] unable to create epoll fd: %d\n", errno );
		exit( 1 );
	}
	epe.events = EPOLLIN;
	epe.data.fd = rcv_fd;

	if( epoll_ctl( ep_fd, EPOLL_CTL_ADD, rcv_fd, &epe ) != 0 )  {
		fprintf( stderr, "[FAIL] epoll_ctl status not 0 : %s\n", strerror( errno ) );
		exit( 1 );
	}

	sbuf = rmr_alloc_msg( mrc, 256 );	// alloc first send buffer; subsequent buffers allcoated on send
	rbuf = NULL;						// don't need to alloc receive buffer

	while( ! rmr_ready( mrc ) ) {		// must have a route table before we can send; wait til RMr say it has one
		sleep( 1 );
	}
	fprintf( stderr, "<DEMO> rmr is ready\n" );
	

	while( 1 ) {										// send messages until the cows come home
		snprintf( sbuf->payload, 200, "count=%d received= %d ts=%lld %d stand up and cheer!", 	// create the payload
			count, rcvd_count, (long long) time( NULL ), rand() );

		sbuf->mtype = mtype;							// fill in the message bits
		sbuf->len =  strlen( sbuf->payload ) + 1;		// our receiver likely wants a nice acsii-z string
		sbuf->state = 0;
		sbuf->sub_id = -1;
		sbuf = rmr_send_msg( mrc, sbuf );				// send it (send returns an empty payload on success, or the original payload on fail/retry)
		fprintf( stderr, "sbuf->state %d\n", sbuf->state );
		while( sbuf->state == RMR_ERR_RETRY ) {			// soft failure (device busy?) retry
			sbuf = rmr_send_msg( mrc, sbuf );			// retry send until it's good (simple test; real programmes should do better)
		}

		if ( sbuf->state == RMR_OK ) {
			fprintf( stderr, "<DEMO> rmr ok\n" );
		}

		count++;

		while( (nready = epoll_wait( ep_fd, events, 1, 0 )) > 0 ) {	// if something ready to receive (non-blocking check)
			if( events[0].data.fd == rcv_fd ) {             // we only are waiting on 1 thing, so [0] is ok
				errno = 0;
				rbuf = rmr_rcv_msg( mrc, rbuf );
				if( rbuf ) {
					rcvd_count++;
				}
			}
		}

		if( (count % stats_freq) == 0 ) {
			fprintf( stderr, "<DEMO> sent %d   received %d\n", count, rcvd_count );
		}

		usleep( delay );
	}
}

xApp Receiver application source code:
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <rmr/rmr.h>


int main( int argc, char** argv ) {
	void* mrc;      					// msg router context
	long long total = 0;
	rmr_mbuf_t* msg = NULL;				// message received
	int stat_freq = 10;				// write stats after reciving this many messages
	int i;
	char*	listen_port = "4560";		// default to what has become the standard RMR port
	long long count = 0;
	long long bad = 0;
	long long empty = 0;

	if( argc > 1 ) {
		listen_port = argv[1];
	}
	if( argc > 2 ) {
		stat_freq = atoi( argv[2] );
	}
	fprintf( stderr, "<DEMO> listening on port: %s\n", listen_port );
	fprintf( stderr, "<DEMO> stats will be reported every %d messages\n", stat_freq );

	mrc = rmr_init( listen_port, RMR_MAX_RCV_BYTES, RMRFL_NONE );	// start your engines!
	if( mrc == NULL ) {
		fprintf( stderr, "<DEMO> ABORT:  unable to initialise RMr\n" );
		exit( 1 );
	}

	while( ! rmr_ready( mrc ) ) {								// wait for RMr to load a route table
		fprintf( stderr, "<DEMO> waiting for ready\n" );
		sleep( 3 );
	}
	fprintf( stderr, "<DEMO> rmr now shows ready\n" );

	while( 1 ) {											// forever; ctl-c, kill -15, etc to end
		msg = rmr_rcv_msg( mrc, msg );						// block until one arrives
		
		if( msg ) {
			if( msg->state == RMR_OK ) {
				count++;									// messages received for stats output
			} else {
				bad++;
			}
		} else {
			empty++;
		}

		if( (count % stat_freq) == 0  ) {
			fprintf( stderr, "<DEMO> total msg received: %lld  errors: %lld   empty: %lld\n", count, bad, empty );
		}

	}
}
```

### Use Case Scenario generated from Application Code
```
Given a sender xApp and a receiver xApp
And sender xApp is initialized with a specific listen port, message type, and delay
And receiver xApp is initialized with a specific listen port and stat frequency
When sender xApp sends a message with a specific payload to the receiver xApp via RMR transmission medium
Then the receiver xApp receives the message
And the receiver xApp updates the count of total messages received, errors, and empty messages
And the receiver xApp prints the total messages received, errors, and empty messages every stat frequency.
```