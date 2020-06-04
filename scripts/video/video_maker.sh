#!/bin/bash

print_usage() {
    echo "Usage: $(basename $0) <command> [args]"
    echo "  commands:"
    echo "      download <txt file path: containing the images to download> <download dir>  - Download the images."
    echo "      create_video <options file>                                       - Create video file from images."
    echo "      help                                                                         - Print command help."
}


load_configuration() {
    if [ -r $1 ]; then
        echo $1
        source $1
    else
        echo "Error loading ${1} !"
        exit 1
    fi

    if [ -z "$IMAGE_DIRECTORY" ] ; then
        echo "Error, IMAGE_DIRECTORY not set"
        exit 1
    fi
    if [ -z "$IMAGE_DURATION" ] ; then
        echo "Error, IMAGE_DURATION not set."
        exit 1
    fi
    if [ -z "$OUTPUT_PATH" ] ; then
        echo "Error, OUTPUT_PATH not set."
        exit 1
    fi
    if [ -z "$OUTPUT_FRAMES" ] ; then
        echo "Error, OUTPUT_FRAMES not set."
        exit 1
    fi
    if [ -z "$OUTPUT_IMAGE_LIST" ] ; then
        echo "Error, OUTPUT_IMAGE_LIST not set."
        exit 1
    fi
      if [ -z "$OUTPUT_VIDEO_NAME" ] ; then
        echo "Error, OUTPUT_VIDEO_NAME not set."
        exit 1
    fi

    mkdir -p $OUTPUT_PATH
    LIST_PATH="$OUTPUT_PATH/$OUTPUT_IMAGE_LIST"
    OUTPUT_VIDEO_PATH="$OUTPUT_PATH/$OUTPUT_VIDEO_NAME"
    IMAGE_DIRECTORY_FILES="${IMAGE_DIRECTORY}/*.jpg"   
}

echo "Checking dependencies... "
if [ -z "`command -v wget`" ] || [ -z "`command -v ffmpeg`" ] ; then
    echo "Error, please check the following commands are avilable: wget, ffmpeg."
    echo "Aborting!"
    exit 1
fi

if [ "$1" == "download" ]; then
        if [ -z "$2" ]; then
            echo "Error, please provide images url file as the second argument."
            exit 1
        fi
        if [ !-f "$2" ]; then
            echo "$2 does not exist"
            exit 1
        fi
        if [ -z "$3" ]; then
            echo "Error, please provide download directory as the third argument."
            exit 1
        fi
        echo "Start downloading images... "
        wget --timeout=1 --tries=1 -i $2 -P $3 

elif [ "$1" == "create_video" ]; then
    if [ -z "$2" ]; then
        echo "Error, please provide config file as the second argument."
        exit 1
    fi
    load_configuration $2

    echo $LIST_PATH
    echo "# FFmpeg image list file" > $LIST_PATH
    for filename in $IMAGE_DIRECTORY_FILES; do
        echo "file '${filename}'" >> $LIST_PATH
        echo "duration ${IMAGE_DURATION}" >> $LIST_PATH
    done
    echo "$FFMPEG_PRE_FLAGS -i $LIST_PATH -frames:v $OUTPUT_FRAMES $FFMPEG_ENCODE_FLAGS $OUTPUT_VIDEO_PATH"
    ffmpeg $FFMPEG_PRE_FLAGS -i $LIST_PATH -frames:v $OUTPUT_FRAMES $FFMPEG_ENCODE_FLAGS $OUTPUT_VIDEO_PATH

elif [ "$1" == "help" ]; then
    print_usage
else
    echo "Error, Unknown command."
    print_usage
    exit 1
fi
