all:
	dotnet publish -c Release -r linux-x64 -p:PublishSingleFile=true --self-contained false -p:IncludeNativeLibrariesForSelfExtract=true
	cp -f ./bin/Release/netcoreapp3.1/linux-x64/publish/ipk-sniffer .

	dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true --self-contained false -p:IncludeNativeLibrariesForSelfExtract=true
	cp -f ./bin/Release/netcoreapp3.1/win-x64/publish/ipk-sniffer.exe .

build:
	dotnet build

.PHONY: clean pack
clean:
	rm -rf ./bin ./obj ipk-sniffer ipk-sniffer.exe

pack:
	tar -cvf xglosk01.tar ipk-sniffer.sln ipk-sniffer.csproj Program.cs Sniffer.cs Makefile PacketDotNet.dll SharpPcap.dll README -C dokumentace manual.pdf