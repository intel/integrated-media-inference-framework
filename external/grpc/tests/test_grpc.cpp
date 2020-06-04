
 /*******************************************************************************
 * Copyright 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include <iostream>

#include <grpcpp/grpcpp.h>

// Dummy test just to make sure that the gRPC library was successfully built
int main(int argc, char* argv[])
{
    // Print the gRPC version
    std::cout << "gRPC Library Version: " << grpc::Version() << std::endl;
    return 0;
}
