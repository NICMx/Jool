#!/bin/bash

sudo ip netns exec blue modprobe -r jool
sudo ip netns exec blue modprobe -r jool_siit
sudo ip netns del blue