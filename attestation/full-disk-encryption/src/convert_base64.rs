extern crate base64;
fn main() {
    let quote="4, 0, 2, 0, 129, 0, 0, 0, 0, 0, 0, 0, 147, 154, 114, 51, 247, 156, 76, 169, 148, 10, 13, 179, 149, 127, 6, 7, 24, 50, 204, 54, 8, 137, 243, 230, 150, 8, 156, 57, 248, 36, 22, 58, 0, 0, 0, 0, 4, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 144, 216, 154, 16, 33, 14, 198, 150, 138, 119, 60, 238, 44, 160, 91, 90, 169, 115, 9, 243, 103, 39, 169, 104, 82, 123, 228, 96, 111, 193, 158, 111, 115, 172, 206, 53, 9, 70, 201, 212, 106, 155, 247, 166, 63, 132, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 128, 231, 2, 6, 0, 0, 0, 0, 0, 242, 221, 38, 150, 246, 155, 149, 6, 69, 131, 43, 220, 9, 95, 253, 17, 36, 126, 239, 246, 135, 238, 172, 219, 87, 165, 141, 45, 219, 154, 159, 148, 254, 164, 12, 150, 30, 25, 70, 12, 0, 255, 163, 20, 32, 236, 188, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 214, 177, 209, 114, 128, 188, 195, 28, 13, 162, 231, 10, 110, 235, 249, 82, 130, 198, 189, 41, 102, 207, 207, 242, 35, 138, 80, 158, 90, 233, 53, 249, 88, 190, 217, 168, 93, 226, 1, 186, 149, 250, 181, 216, 179, 21, 116, 241, 63, 32, 235, 145, 238, 37, 36, 1, 220, 142, 6, 199, 181, 226, 83, 121, 193, 238, 197, 184, 100, 4, 12, 124, 130, 141, 241, 128, 78, 89, 108, 61, 12, 115, 147, 237, 130, 134, 58, 207, 61, 231, 22, 14, 47, 228, 0, 16, 238, 207, 196, 47, 244, 212, 146, 120, 191, 219, 176, 199, 126, 87, 15, 68, 144, 207, 241, 10, 46, 225, 172, 17, 251, 210, 194, 180, 159, 166, 207, 163, 207, 26, 28, 183, 85, 199, 37, 34, 221, 138, 104, 158, 157, 71, 144, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62, 204, 16, 0, 0, 116, 140, 96, 212, 167, 137, 85, 243, 167, 21, 157, 170, 202, 141, 155, 206, 64, 14, 32, 223, 20, 133, 13, 83, 215, 111, 195, 141, 143, 140, 11, 87, 219, 31, 171, 255, 206, 178, 179, 41, 189, 202, 142, 157, 192, 91, 0, 105, 208, 239, 62, 196, 76, 232, 76, 101, 204, 140, 134, 206, 115, 229, 210, 162, 130, 249, 210, 246, 178, 254, 92, 192, 178, 46, 32, 151, 149, 175, 181, 110, 139, 20, 241, 87, 195, 105, 163, 187, 171, 96, 107, 87, 45, 37, 7, 100, 65, 101, 34, 165, 111, 244, 191, 145, 198, 94, 61, 64, 217, 92, 6, 54, 26, 133, 45, 229, 156, 188, 174, 101, 66, 160, 152, 162, 75, 174, 180, 71, 6, 0, 70, 16, 0, 0, 2, 2, 24, 26, 3, 255, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 134, 252, 78, 14, 194, 197, 221, 206, 186, 201, 112, 98, 192, 160, 20, 42, 151, 193, 138, 122, 117, 81, 71, 188, 188, 63, 225, 125, 101, 41, 120, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 158, 42, 124, 111, 148, 143, 23, 71, 78, 52, 167, 252, 67, 237, 3, 15, 124, 21, 99, 241, 186, 189, 223, 99, 64, 200, 46, 14, 84, 168, 197, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 175, 98, 14, 47, 140, 22, 245, 164, 1, 148, 46, 81, 34, 100, 162, 35, 27, 255, 111, 231, 21, 29, 53, 17, 42, 58, 29, 22, 134, 129, 128, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 167, 196, 59, 195, 59, 6, 200, 219, 209, 237, 61, 28, 171, 30, 92, 73, 238, 159, 30, 211, 28, 231, 48, 124, 69, 93, 140, 174, 200, 143, 164, 64, 163, 121, 252, 30, 250, 161, 216, 128, 210, 229, 92, 155, 26, 246, 42, 253, 76, 29, 171, 132, 244, 111, 154, 49, 251, 187, 38, 220, 77, 181, 69, 241, 32, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 5, 0, 94, 14, 0, 0, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 69, 56, 68, 67, 67, 66, 74, 97, 103, 65, 119, 73, 66, 65, 103, 73, 85, 72, 120, 108, 104, 84, 90, 66, 103, 48, 109, 114, 87, 110, 109, 112, 80, 117, 112, 109, 80, 115, 100, 110, 65, 79, 88, 52, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 119, 10, 99, 68, 69, 105, 77, 67, 65, 71, 65, 49, 85, 69, 65, 119, 119, 90, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 66, 68, 83, 121, 66, 81, 98, 71, 70, 48, 90, 109, 57, 121, 98, 83, 66, 68, 81, 84, 69, 97, 77, 66, 103, 71, 65, 49, 85, 69, 67, 103, 119, 82, 10, 83, 87, 53, 48, 90, 87, 119, 103, 81, 50, 57, 121, 99, 71, 57, 121, 89, 88, 82, 112, 98, 50, 52, 120, 70, 68, 65, 83, 66, 103, 78, 86, 66, 65, 99, 77, 67, 49, 78, 104, 98, 110, 82, 104, 73, 69, 78, 115, 89, 88, 74, 104, 77, 81, 115, 119, 67, 81, 89, 68, 86, 81, 81, 73, 10, 68, 65, 74, 68, 81, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 66, 104, 77, 67, 86, 86, 77, 119, 72, 104, 99, 78, 77, 106, 81, 119, 78, 84, 65, 50, 77, 68, 81, 120, 78, 84, 69, 119, 87, 104, 99, 78, 77, 122, 69, 119, 78, 84, 65, 50, 77, 68, 81, 120, 78, 84, 69, 119, 10, 87, 106, 66, 119, 77, 83, 73, 119, 73, 65, 89, 68, 86, 81, 81, 68, 68, 66, 108, 74, 98, 110, 82, 108, 98, 67, 66, 84, 82, 49, 103, 103, 85, 69, 78, 76, 73, 69, 78, 108, 99, 110, 82, 112, 90, 109, 108, 106, 89, 88, 82, 108, 77, 82, 111, 119, 71, 65, 89, 68, 86, 81, 81, 75, 10, 68, 66, 70, 74, 98, 110, 82, 108, 98, 67, 66, 68, 98, 51, 74, 119, 98, 51, 74, 104, 100, 71, 108, 118, 98, 106, 69, 85, 77, 66, 73, 71, 65, 49, 85, 69, 66, 119, 119, 76, 85, 50, 70, 117, 100, 71, 69, 103, 81, 50, 120, 104, 99, 109, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 10, 66, 65, 103, 77, 65, 107, 78, 66, 77, 81, 115, 119, 67, 81, 89, 68, 86, 81, 81, 71, 69, 119, 74, 86, 85, 122, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 65, 43, 102, 10, 77, 105, 90, 110, 57, 80, 119, 50, 82, 69, 79, 81, 74, 105, 98, 105, 65, 57, 83, 48, 50, 47, 52, 65, 52, 102, 117, 53, 84, 80, 111, 113, 113, 112, 47, 106, 119, 47, 114, 101, 118, 72, 82, 108, 112, 69, 51, 74, 105, 107, 109, 117, 50, 75, 51, 119, 55, 68, 57, 113, 118, 90, 72, 75, 10, 65, 47, 73, 85, 54, 99, 117, 116, 70, 116, 66, 43, 70, 74, 117, 107, 104, 53, 67, 106, 103, 103, 77, 77, 77, 73, 73, 68, 67, 68, 65, 102, 66, 103, 78, 86, 72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 83, 86, 98, 49, 51, 78, 118, 82, 118, 104, 54, 85, 66, 74, 121, 100, 84, 48, 10, 77, 56, 52, 66, 86, 119, 118, 101, 86, 68, 66, 114, 66, 103, 78, 86, 72, 82, 56, 69, 90, 68, 66, 105, 77, 71, 67, 103, 88, 113, 66, 99, 104, 108, 112, 111, 100, 72, 82, 119, 99, 122, 111, 118, 76, 50, 70, 119, 97, 83, 53, 48, 99, 110, 86, 122, 100, 71, 86, 107, 99, 50, 86, 121, 10, 100, 109, 108, 106, 90, 88, 77, 117, 97, 87, 53, 48, 90, 87, 119, 117, 89, 50, 57, 116, 76, 51, 78, 110, 101, 67, 57, 106, 90, 88, 74, 48, 97, 87, 90, 112, 89, 50, 70, 48, 97, 87, 57, 117, 76, 51, 89, 48, 76, 51, 66, 106, 97, 50, 78, 121, 98, 68, 57, 106, 89, 84, 49, 119, 10, 98, 71, 70, 48, 90, 109, 57, 121, 98, 83, 90, 108, 98, 109, 78, 118, 90, 71, 108, 117, 90, 122, 49, 107, 90, 88, 73, 119, 72, 81, 89, 68, 86, 82, 48, 79, 66, 66, 89, 69, 70, 80, 111, 118, 113, 122, 51, 74, 67, 75, 74, 84, 87, 109, 88, 79, 122, 120, 53, 78, 76, 113, 55, 113, 10, 106, 86, 52, 99, 77, 65, 52, 71, 65, 49, 85, 100, 68, 119, 69, 66, 47, 119, 81, 69, 65, 119, 73, 71, 119, 68, 65, 77, 66, 103, 78, 86, 72, 82, 77, 66, 65, 102, 56, 69, 65, 106, 65, 65, 77, 73, 73, 67, 79, 81, 89, 74, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 10, 66, 73, 73, 67, 75, 106, 67, 67, 65, 105, 89, 119, 72, 103, 89, 75, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 81, 81, 81, 84, 68, 100, 50, 71, 73, 113, 89, 89, 47, 77, 85, 83, 109, 115, 51, 113, 121, 54, 104, 105, 84, 67, 67, 65, 87, 77, 71, 67, 105, 113, 71, 10, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 119, 103, 103, 70, 84, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 66, 65, 103, 69, 67, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 67, 65, 103, 69, 67, 10, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 68, 65, 103, 69, 67, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 69, 65, 103, 69, 67, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 10, 65, 81, 73, 70, 65, 103, 69, 68, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 71, 65, 103, 69, 66, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 72, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 10, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 73, 65, 103, 69, 68, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 74, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 75, 65, 103, 69, 65, 10, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 76, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 77, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 10, 65, 81, 73, 78, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 79, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 80, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 10, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 81, 65, 103, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 82, 65, 103, 69, 78, 77, 66, 56, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 73, 83, 66, 66, 65, 67, 10, 65, 103, 73, 67, 65, 119, 69, 65, 65, 119, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 77, 66, 65, 71, 67, 105, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 77, 69, 65, 103, 65, 65, 77, 66, 81, 71, 67, 105, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 81, 69, 10, 66, 112, 68, 65, 98, 119, 65, 65, 65, 68, 65, 80, 66, 103, 111, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 70, 67, 103, 69, 66, 77, 66, 52, 71, 67, 105, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 89, 69, 69, 78, 76, 83, 98, 57, 101, 53, 82, 73, 90, 80, 10, 118, 51, 113, 89, 73, 121, 82, 76, 111, 97, 77, 119, 82, 65, 89, 75, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 66, 122, 65, 50, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 99, 66, 65, 81, 72, 47, 77, 66, 65, 71, 67, 121, 113, 71, 10, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 99, 67, 65, 81, 69, 65, 77, 66, 65, 71, 67, 121, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 99, 68, 65, 81, 72, 47, 77, 65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 66, 65, 77, 67, 65, 48, 103, 65, 77, 69, 85, 67, 10, 73, 69, 47, 52, 69, 105, 85, 82, 119, 103, 78, 76, 65, 50, 117, 119, 99, 89, 90, 103, 78, 55, 83, 51, 57, 121, 120, 109, 87, 55, 107, 72, 98, 108, 99, 80, 100, 108, 121, 55, 120, 117, 75, 112, 65, 105, 69, 65, 54, 100, 102, 121, 108, 105, 122, 88, 84, 51, 101, 121, 113, 117, 86, 97, 10, 71, 99, 119, 117, 111, 82, 112, 66, 115, 122, 56, 74, 78, 55, 81, 106, 90, 89, 104, 122, 113, 112, 74, 102, 50, 103, 85, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 108, 106, 67, 67, 65, 106, 50, 103, 65, 119, 73, 66, 65, 103, 73, 86, 65, 74, 86, 118, 88, 99, 50, 57, 71, 43, 72, 112, 81, 69, 110, 74, 49, 80, 81, 122, 122, 103, 70, 88, 67, 57, 53, 85, 77, 65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 66, 65, 77, 67, 10, 77, 71, 103, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 77, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 70, 78, 72, 87, 67, 66, 83, 98, 50, 57, 48, 73, 69, 78, 66, 77, 82, 111, 119, 71, 65, 89, 68, 86, 81, 81, 75, 68, 66, 70, 74, 98, 110, 82, 108, 98, 67, 66, 68, 10, 98, 51, 74, 119, 98, 51, 74, 104, 100, 71, 108, 118, 98, 106, 69, 85, 77, 66, 73, 71, 65, 49, 85, 69, 66, 119, 119, 76, 85, 50, 70, 117, 100, 71, 69, 103, 81, 50, 120, 104, 99, 109, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 103, 77, 65, 107, 78, 66, 77, 81, 115, 119, 10, 67, 81, 89, 68, 86, 81, 81, 71, 69, 119, 74, 86, 85, 122, 65, 101, 70, 119, 48, 120, 79, 68, 65, 49, 77, 106, 69, 120, 77, 68, 85, 119, 77, 84, 66, 97, 70, 119, 48, 122, 77, 122, 65, 49, 77, 106, 69, 120, 77, 68, 85, 119, 77, 84, 66, 97, 77, 72, 65, 120, 73, 106, 65, 103, 10, 66, 103, 78, 86, 66, 65, 77, 77, 71, 85, 108, 117, 100, 71, 86, 115, 73, 70, 78, 72, 87, 67, 66, 81, 81, 48, 115, 103, 85, 71, 120, 104, 100, 71, 90, 118, 99, 109, 48, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 10, 73, 69, 78, 118, 99, 110, 66, 118, 99, 109, 70, 48, 97, 87, 57, 117, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 10, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 89, 84, 65, 108, 86, 84, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 78, 83, 66, 47, 55, 116, 50, 49, 108, 88, 83, 79, 10, 50, 67, 117, 122, 112, 120, 119, 55, 52, 101, 74, 66, 55, 50, 69, 121, 68, 71, 103, 87, 53, 114, 88, 67, 116, 120, 50, 116, 86, 84, 76, 113, 54, 104, 75, 107, 54, 122, 43, 85, 105, 82, 90, 67, 110, 113, 82, 55, 112, 115, 79, 118, 103, 113, 70, 101, 83, 120, 108, 109, 84, 108, 74, 108, 10, 101, 84, 109, 105, 50, 87, 89, 122, 51, 113, 79, 66, 117, 122, 67, 66, 117, 68, 65, 102, 66, 103, 78, 86, 72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 81, 105, 90, 81, 122, 87, 87, 112, 48, 48, 105, 102, 79, 68, 116, 74, 86, 83, 118, 49, 65, 98, 79, 83, 99, 71, 114, 68, 66, 83, 10, 66, 103, 78, 86, 72, 82, 56, 69, 83, 122, 66, 74, 77, 69, 101, 103, 82, 97, 66, 68, 104, 107, 70, 111, 100, 72, 82, 119, 99, 122, 111, 118, 76, 50, 78, 108, 99, 110, 82, 112, 90, 109, 108, 106, 89, 88, 82, 108, 99, 121, 53, 48, 99, 110, 86, 122, 100, 71, 86, 107, 99, 50, 86, 121, 10, 100, 109, 108, 106, 90, 88, 77, 117, 97, 87, 53, 48, 90, 87, 119, 117, 89, 50, 57, 116, 76, 48, 108, 117, 100, 71, 86, 115, 85, 48, 100, 89, 85, 109, 57, 118, 100, 69, 78, 66, 76, 109, 82, 108, 99, 106, 65, 100, 66, 103, 78, 86, 72, 81, 52, 69, 70, 103, 81, 85, 108, 87, 57, 100, 10, 122, 98, 48, 98, 52, 101, 108, 65, 83, 99, 110, 85, 57, 68, 80, 79, 65, 86, 99, 76, 51, 108, 81, 119, 68, 103, 89, 68, 86, 82, 48, 80, 65, 81, 72, 47, 66, 65, 81, 68, 65, 103, 69, 71, 77, 66, 73, 71, 65, 49, 85, 100, 69, 119, 69, 66, 47, 119, 81, 73, 77, 65, 89, 66, 10, 65, 102, 56, 67, 65, 81, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 68, 82, 119, 65, 119, 82, 65, 73, 103, 88, 115, 86, 107, 105, 48, 119, 43, 105, 54, 86, 89, 71, 87, 51, 85, 70, 47, 50, 50, 117, 97, 88, 101, 48, 89, 74, 68, 106, 49, 85, 101, 10, 110, 65, 43, 84, 106, 68, 49, 97, 105, 53, 99, 67, 73, 67, 89, 98, 49, 83, 65, 109, 68, 53, 120, 107, 102, 84, 86, 112, 118, 111, 52, 85, 111, 121, 105, 83, 89, 120, 114, 68, 87, 76, 109, 85, 82, 52, 67, 73, 57, 78, 75, 121, 102, 80, 78, 43, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 106, 122, 67, 67, 65, 106, 83, 103, 65, 119, 73, 66, 65, 103, 73, 85, 73, 109, 85, 77, 49, 108, 113, 100, 78, 73, 110, 122, 103, 55, 83, 86, 85, 114, 57, 81, 71, 122, 107, 110, 66, 113, 119, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 119, 10, 97, 68, 69, 97, 77, 66, 103, 71, 65, 49, 85, 69, 65, 119, 119, 82, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 74, 118, 98, 51, 81, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 69, 78, 118, 10, 99, 110, 66, 118, 99, 109, 70, 48, 97, 87, 57, 117, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 67, 122, 65, 74, 10, 66, 103, 78, 86, 66, 65, 89, 84, 65, 108, 86, 84, 77, 66, 52, 88, 68, 84, 69, 52, 77, 68, 85, 121, 77, 84, 69, 119, 78, 68, 85, 120, 77, 70, 111, 88, 68, 84, 81, 53, 77, 84, 73, 122, 77, 84, 73, 122, 78, 84, 107, 49, 79, 86, 111, 119, 97, 68, 69, 97, 77, 66, 103, 71, 10, 65, 49, 85, 69, 65, 119, 119, 82, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 74, 118, 98, 51, 81, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 69, 78, 118, 99, 110, 66, 118, 99, 109, 70, 48, 10, 97, 87, 57, 117, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 89, 84, 10, 65, 108, 86, 84, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 67, 54, 110, 69, 119, 77, 68, 73, 89, 90, 79, 106, 47, 105, 80, 87, 115, 67, 122, 97, 69, 75, 105, 55, 10, 49, 79, 105, 79, 83, 76, 82, 70, 104, 87, 71, 106, 98, 110, 66, 86, 74, 102, 86, 110, 107, 89, 52, 117, 51, 73, 106, 107, 68, 89, 89, 76, 48, 77, 120, 79, 52, 109, 113, 115, 121, 89, 106, 108, 66, 97, 108, 84, 86, 89, 120, 70, 80, 50, 115, 74, 66, 75, 53, 122, 108, 75, 79, 66, 10, 117, 122, 67, 66, 117, 68, 65, 102, 66, 103, 78, 86, 72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 81, 105, 90, 81, 122, 87, 87, 112, 48, 48, 105, 102, 79, 68, 116, 74, 86, 83, 118, 49, 65, 98, 79, 83, 99, 71, 114, 68, 66, 83, 66, 103, 78, 86, 72, 82, 56, 69, 83, 122, 66, 74, 10, 77, 69, 101, 103, 82, 97, 66, 68, 104, 107, 70, 111, 100, 72, 82, 119, 99, 122, 111, 118, 76, 50, 78, 108, 99, 110, 82, 112, 90, 109, 108, 106, 89, 88, 82, 108, 99, 121, 53, 48, 99, 110, 86, 122, 100, 71, 86, 107, 99, 50, 86, 121, 100, 109, 108, 106, 90, 88, 77, 117, 97, 87, 53, 48, 10, 90, 87, 119, 117, 89, 50, 57, 116, 76, 48, 108, 117, 100, 71, 86, 115, 85, 48, 100, 89, 85, 109, 57, 118, 100, 69, 78, 66, 76, 109, 82, 108, 99, 106, 65, 100, 66, 103, 78, 86, 72, 81, 52, 69, 70, 103, 81, 85, 73, 109, 85, 77, 49, 108, 113, 100, 78, 73, 110, 122, 103, 55, 83, 86, 10, 85, 114, 57, 81, 71, 122, 107, 110, 66, 113, 119, 119, 68, 103, 89, 68, 86, 82, 48, 80, 65, 81, 72, 47, 66, 65, 81, 68, 65, 103, 69, 71, 77, 66, 73, 71, 65, 49, 85, 100, 69, 119, 69, 66, 47, 119, 81, 73, 77, 65, 89, 66, 65, 102, 56, 67, 65, 81, 69, 119, 67, 103, 89, 73, 10, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 68, 83, 81, 65, 119, 82, 103, 73, 104, 65, 79, 87, 47, 53, 81, 107, 82, 43, 83, 57, 67, 105, 83, 68, 99, 78, 111, 111, 119, 76, 117, 80, 82, 76, 115, 87, 71, 102, 47, 89, 105, 55, 71, 83, 88, 57, 52, 66, 103, 119, 84, 119, 103, 10, 65, 105, 69, 65, 52, 74, 48, 108, 114, 72, 111, 77, 115, 43, 88, 111, 53, 111, 47, 115, 88, 54, 79, 57, 81, 87, 120, 72, 82, 65, 118, 90, 85, 71, 79, 100, 82, 81, 55, 99, 118, 113, 82, 88, 97, 113, 73, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0";
    let mut hex: Vec<String> = quote.iter().map(|n| format!("{:02x}", n)).collect();
    let mut hex_string = hex.join("");
    //println!("Quote Bytes: {:?}", quote);
    println!("quote: {:?}", hex_string);
    println!("Quote: {}", base64::encode(&hex_string));
}
