#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <glm/glm.hpp>
#include <glm/gtc/matrix_transform.hpp>
#include <glm/gtc/type_ptr.hpp>

#include <learnopengl/shader_m.h>
#include <learnopengl/camera.h>

#include <iostream>

void framebuffer_size_callback(GLFWwindow* window, int width, int height);
void processInput(GLFWwindow *window);

const unsigned int SCR_WIDTH = 400;
const unsigned int SCR_HEIGHT = 200;
float lastX = SCR_WIDTH / 2.0f;
float lastY = SCR_HEIGHT / 2.0f;
bool firstMouse = true;
Camera camera(glm::vec3(0.0f, 0.0f, 25.0f));

// lighting
glm::vec3 lightPos(1.2f, 1.0f, 23.0f);
glm::vec3 lightColor(1.0f, 0.63f, 1.0f);

struct Vertex {
    // position
    float Position[3];
    // normal
    float Normal[3];
    // texCoords
    float TexCoords[2];
};

struct BlobHeader {
    uint32_t numVertices;
    uint32_t numIndices;
};


int main()
{

    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWwindow* window = glfwCreateWindow(SCR_WIDTH, SCR_HEIGHT, "where am i?", NULL, NULL);
    if (window == NULL)
    {
        std::cout << "create window error" << std::endl;
        glfwTerminate();
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSetFramebufferSizeCallback(window, framebuffer_size_callback);

    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress))
    {
        std::cout << "init lib failed" << std::endl;
        return -1;
    }

    glEnable(GL_DEPTH_TEST);

    Shader lightingShader("a2.do", "a1.do");
    std::vector<Vertex> vertices;
    std::vector<unsigned int> indices;
    BlobHeader hdr;
    {
        FILE* fp = fopen("dat.bin", "rb");
        if (!fp) {
            std::cerr << "Failed to open dat.bin" << std::endl;
            return -1;
        }

        if (fread(&hdr, sizeof(BlobHeader), 1, fp) != 1) {
            std::cerr << "Failed to read dat.bin" << std::endl;
            return -1;
        }

        vertices.resize(hdr.numVertices);
        indices.resize(hdr.numIndices);

        if (fread(const_cast<Vertex*>(vertices.data()), sizeof(Vertex), hdr.numVertices, fp) != hdr.numVertices) {
            std::cerr << "Failed to read dat.bin" << std::endl;
            return -1;
        }

        if (fread(const_cast<unsigned int*>(indices.data()), sizeof(unsigned int), hdr.numIndices, fp) != hdr.numIndices) {
            std::cerr << "Failed to read dat.bin" << std::endl;
            return -1;
        }

        //printf("Vertices: %zd, Indices: %zd\n", vertices.size(), indices.size());

    }

    unsigned int VBO, cubeVAO;
    glGenVertexArrays(1, &cubeVAO);
    glGenBuffers(1, &VBO);

    glBindBuffer(GL_ARRAY_BUFFER, VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(Vertex) * vertices.size(), vertices.data(), GL_STATIC_DRAW);

    glBindVertexArray(cubeVAO);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), (void*)0);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), (void*)(3 * sizeof(float)));
    glEnableVertexAttribArray(1);

    // render loop
    while (!glfwWindowShouldClose(window))
    {

        processInput(window);

        glClearColor(0.75f, 0.55f, 0.35f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        lightingShader.use();
        lightingShader.setVec3("utc", 0.37f, 0.77f, 0.61f);
        //lightingShader.setVec3("objectColor", 0.37f, 0.77f, 0.61f);
        lightColor.x = sin(glfwGetTime() * 2.0f);
        lightColor.y = sin(glfwGetTime() * 0.7f);
        lightColor.z = sin(glfwGetTime() * 1.3f);

        lightingShader.setVec3("gjm", lightColor);
        //lightingShader.setVec3("lightColor", lightColor);
        lightPos.x = 1.0f + sin(glfwGetTime()) * 2.0f;
        lightPos.y = sin(glfwGetTime() / 2.0f) * 1.0f;

        lightingShader.setVec3("ngu", lightPos);
        //lightingShader.setVec3("lightPos", lightPos);

        glm::mat4 projection = glm::perspective(glm::radians(camera.Zoom), (float)SCR_WIDTH / (float)SCR_HEIGHT, 0.1f, 100.0f);
        glm::mat4 view = camera.GetViewMatrix();

        lightingShader.setMat4("ojc", projection);
        //lightingShader.setMat4("projection", projection);

        lightingShader.setMat4("kkb", view);
        //lightingShader.setMat4("view", view);

        glm::mat4 model = glm::mat4(1.0f);
        lightingShader.setMat4("fdc", model);
        //lightingShader.setMat4("model", model);

        glBindVertexArray(cubeVAO);
        glDrawElements(GL_TRIANGLES, indices.size(), GL_UNSIGNED_INT, indices.data());
        glfwSwapBuffers(window);
        glfwPollEvents();
    }

    glDeleteVertexArrays(1, &cubeVAO);
    // glDeleteVertexArrays(1, &lightCubeVAO);
    glDeleteBuffers(1, &VBO);
    glfwTerminate();
    return 0;
}


void processInput(GLFWwindow *window)
{
    if (glfwGetKey(window, GLFW_KEY_ESCAPE) == GLFW_PRESS)
        glfwSetWindowShouldClose(window, true);
}


void framebuffer_size_callback(GLFWwindow* window, int width, int height)
{
    glViewport(0, 0, width, height);
}