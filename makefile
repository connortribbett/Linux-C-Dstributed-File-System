all: dfc.c dfs.c dfsys.h
		gcc -o dfc dfc.c dfsys.h -lpthread -lcrypto
		gcc -o dfs dfs.c dfsys.h -lpthread -lcrypto
clean:
		$(RM) dfc dfs