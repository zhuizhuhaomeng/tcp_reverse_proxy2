all:proxy_server proxy_agent

proxy_server:proxy_server.cpp
	g++ -g -o proxy_server proxy_server.cpp -levent

proxy_agent:proxy_agent.cpp
	g++ -g -o proxy_agent proxy_agent.cpp -lpthread

clean:
	@rm -f proxy_agent proxy_server
	@rm -f proxy_agent.o proxy_server.o
