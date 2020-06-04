# Video Maker

Creates h264 and rgb video files from images.

Create video from images instructions:
1. Create a list with URLs of jpg images you want to download.
   You can find an existing list on ImageNet project. Go to: http://image-net.org/synset?wnid=n02084071
   select a topic and go to Downloads tab. Download the list by right clicking on "URLs" and select "Save link as".
2. Download all the images into a folder by running: 
```
video_maker.sh download <path_to_url_list_file> <destionation_path/>
```
3. Create a config file - you can start with h264_video.conf.example or rgb_video.conf.example
4. Create a video from the images by running:
```
video_maker.sh create_video <path_to_conf_file>
```
