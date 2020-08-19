# How to scan a docker image?
There are couple of ways to scan a docker image using `cve-bin-tool`.
1. You can scan a docker image by installing and running `cve-bin-tool` inside
a docker container. 
2. You can export the directory on host and scan it on host. 

We are going to scan `/usr/bin` directory of ubuntu:latest docker image for 
demonstration purpose but you can use same recipe to scan directory of your
interest. 

## Install and run CVE Binary Tool inside container

Let's first create a docker instance of the image we want to scan using following
command:
```console
docker run -it -d --name cve_scan ubuntu  --entrypoint bash 
```
This will create new instance of ubuntu image and run it in the background. You 
can check if your container is running or not using `docker ps`.
 > Note: you may need to use sudo if current user isn't in the docker group. 

Now let’s go inside the container using the docker exec command and install python
in it.
```console
docker exec -it cve_scan bash
```
In this example we have defined container name as `cve_scan`. You will get a random
name if you have not defined while running the container initially.

Update the container and install `python3` on it.
```console
apt-get update
apt-get install python3
apt-get install python3-pip
```
> Note: this step is distro specific if your container is based on different 
distro (Ex: centos) checkout official documentation of that specific distro 
for installing `python3` in it.

Now let's install `cve-bin-tool` in our container.

```console
pip3 install cve-bin-tool
```
This will install latest version of `cve-bin-tool` from PyPI.

You can also install latest development version from our github repository using
following command
```console
pip3 install git+https://github.com/intel/cve-bin-tool
```
After all the things done check the version of `cve-bin-tool` using the command.
```console
cve-bin-tool -V
```
If there is output then You have installed `cve-bin-tool` successfully in the 
docker container.

Now let's scan `/usr/bin` directory and export report to the host using following
command.
```console
cve-bin-tool /usr/bin -f csv -o usr_bin_cve.csv
```

This will take sometime and after generation of the report, you have to export it
to the host. You first need to exit current docker session by typing `exit` in
the container terminal. Now let's copy report from container to the host.
```console
docker cp cve_scan:~/usr_bin_cve.csv ~/Documents/usr_bin_cve.csv
```
This will save CVE report of scanned docker directory in the 
`~/Documents/usr_bin_cve.csv`. 

## Export directory from container and scan

Assuming, you already have created docker instance named `cve_scan` as mentioned
above. You can export directory you want to scan to the host and scan there.

```console
docker cp cve_scan:/usr/bin/ ~/scan
```

This will copy all files and directories from `/usr/bin` to `/scan` and now you
can scan `scan` directory with `cve-bin-tool` normally.

> Note: You may want to use `docker cp -a` if you want to copy all uid/gid info.

```console
cve-bin-tool scan [OPTIONS]
```

> Note: This method assumes you already have installed cve-bin-tool on host. If
 you haven't install it with `pip3 install cve-bin-tool`.

Both of the above mentioned methods will help you scan a docker image and you can
choose one over another. Second method is comparatively easier than first but has
overhead of copying all data from container to host while first method requires
you to install `cve-bin-tool` in docker container which can take around 10 minutes. 
You can automate both processes with simple `bash` script. 
