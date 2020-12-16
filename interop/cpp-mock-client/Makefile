BUILD_DIR=build
APP_NAME=mock_client

PHONY: run format clean cclean

${BUILD_DIR}:
	cmake -B${BUILD_DIR} .

${BUILD_DIR}/${APP_NAME}: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target ${APP_NAME}

run: ${BUILD_DIR}/${APP_NAME}
	./${BUILD_DIR}/${APP_NAME}

format:
	clang-format -i -style=Mozilla *.cpp

clean: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target ${APP_NAME}

cclean:
	rm -rf ${BUILD_DIR}
