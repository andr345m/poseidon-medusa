### 这个东西是干什么的呢，我只能说“你懂的”了……

### 需要先安装 Poseidon：

    https://github.com/lhmouse/poseidon

### 确保以下依赖为最新：

    automake
    autoconf
    libtool
    pkg-config
    gettext
    make
    g++
    libboost-dev
    libmysqlclient-dev
    libssl-dev
    libgoogle-perftools-dev

### 编译 Poseidon：

    git clone https://github.com/lhmouse/poseidon.git
    cd poseidon
    ./reconfig_release_cxx11.sh
    make -j3

### 安装 Poseidon（不建议使用 sudo make install）：

    # Debian：
    # （需要先安装 checkinstall）
    sudo ./makedeb.sh

    # 非 Debian 的 Linux 发行版：
    # 请使用系统自带的包管理器安装。

### 编译 Medusa：

    git clone https://github.com/lhmouse/poseidon-medusa.git
    cd poseidon-medusa
    ./reconfig_release_cxx11.sh
    make -j3

### 启动 Medusa：

    # 不需要 sudo。
    # 加 -d 表示使用 gdb 启动，加 -v 表示使用 valgrind 启动（建议关掉 tcmalloc）。
    # 若直接启动，ssh 掉线之后会结束，可以用 nohup 或 screen 启动挂在后台。
    ./runserver.sh

### 修改配置文件（配置文件内有注释）：

    # 使用 ./runserver.sh：
    cd etc/poseidon-medusa/
    cp medusa-template.conf medusa.conf
    nano medusa.conf

    # 使用 ./makedeb.sh 创建 .deb 包并安装后：
    cd /usr/etc/poseidon-medusa/
    sudo cp medusa-template.conf medusa.conf
    sudo nano medusa.conf

### 问题反馈

  请联系 lh_mouse at 126 dot com（注明 Medusa 相关）。