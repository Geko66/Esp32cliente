#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"


// Declarar manejador de eventos de Wi-Fi
static esp_err_t wifi_event_handler(void *ctx, esp_event_handler_t *event)
{
    return ESP_OK;
}

// Enviar mensaje al servidor
void send_message(char *message)
{
    // Configurar solicitud HTTP POST
    esp_http_client_config_t config = {
        .url = "http://192.168.1.69:500/enviarMSG",
        .method = HTTP_METHOD_POST,
        .buffer_size = strlen(message) + 32,
        .timeout_ms = 10000,
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "X-Server-ID", "server1");
    esp_http_client_set_header(client, "Content-Type", "application/json");

    // Crear cuerpo de solicitud JSON
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "message", message);
    char *post_data = cJSON_Print(root);
    cJSON_Delete(root);

    // Enviar solicitud y recibir respuesta
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE("send_message", "HTTP request failed: %s", esp_err_to_name(err));
        free(post_data);
        esp_http_client_cleanup(client);
        return;
    }

    // Analizar respuesta JSON
    char *response = (char *)malloc(esp_http_client_get_content_length(client) + 1);
    esp_http_client_read_response(client, response, esp_http_client_get_content_length(client));
    response[esp_http_client_get_content_length(client)] = '\0';
    ESP_LOGI("send_message", "HTTP response: %s", response);
    cJSON *json = cJSON_Parse(response);
    cJSON *success = cJSON_GetObjectItem(json, "success");
    if (success != NULL && cJSON_IsBool(success) && success->valueint == 1) {
        ESP_LOGI("send_message", "Message sent successfully");
    } else {
        ESP_LOGE("send_message", "Failed to send message");
    }
    cJSON_Delete(json);
    free(response);
    free(post_data);
    esp_http_client_cleanup(client);
}

// Obtener mensajes del servidor
void get_messages()
{
    // Configurar solicitud HTTP GET
    esp_http_client_config_t config = {
        .url = "http://192.168.1.69:500/mensajes",
        .method = HTTP_METHOD_GET,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "X-Server-ID", "server1");

    // Enviar solicitud y recibir respuesta
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE("get_messages", "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return;
    }

    // Leer respuesta
    char *response = (char *)malloc(esp_http_client_get_content_length(client) + 1);
    esp_http_client_read_response(client, response, esp_http_client_get_content_length(client));
response[esp_http_client_get_content_length(client)] = '\0';
ESP_LOGI("get_messages", "HTTP response: %s", response);
// Analizar respuesta JSON
cJSON *json = cJSON_Parse(response);
cJSON *messages = cJSON_GetObjectItem(json, "messages");
cJSON *publica_server = cJSON_GetObjectItem(json, "publica_server");
if (messages != NULL && cJSON_IsArray(messages)) {
    ESP_LOGI("get_messages", "Received %d messages", cJSON_GetArraySize(messages));
    for (int i = 0; i < cJSON_GetArraySize(messages); i++) {
        cJSON *message = cJSON_GetArrayItem(messages, i);
        cJSON *text = cJSON_GetObjectItem(message, "text");
        cJSON *timestamp = cJSON_GetObjectItem(message, "timestamp");
        if (text != NULL && cJSON_IsString(text) && timestamp != NULL && cJSON_IsNumber(timestamp)) {
            ESP_LOGI("get_messages", "Message %d: %s (%lld)", i+1, text->valuestring, (long long int)timestamp->valueint);
        }
    }
}
if (publica_server != NULL && cJSON_IsBool(publica_server)) {
    ESP_LOGI("get_messages", "Publica server: %s", publica_server->valueint == 1 ? "true" : "false");
}
cJSON_Delete(json);
free(response);
esp_http_client_cleanup(client);
}
// Programa principal
void app_main()
{

// Iniciar Wi-Fi
esp_netif_init();
esp_event_loop_run(wifi_event_handler,NULL);
wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
esp_wifi_init(&wifi_config);
esp_wifi_set_storage(WIFI_STORAGE_RAM);
esp_wifi_set_mode(WIFI_MODE_STA);
wifi_config_t sta_config = {
.sta = {
.ssid = "V1AHC9",
.password = "pMadrid77",
.scan_method = WIFI_FAST_SCAN,
.sort_method = WIFI_CONNECT_AP_BY_SIGNAL,
.threshold.rssi = -127,
.threshold.authmode = WIFI_AUTH_WPA2_PSK,
},
};
esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_config);
esp_wifi_start();
// Esperar a que se conecte a Wi-Fi
wifi_ap_record_t ap_info;
while (1) {
    esp_wifi_sta_get_ap_info(&ap_info);
    if (strlen((char *)ap_info.ssid) > 0 && ap_info.rssi >= -60) {
        break;
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);
}

// Iniciar servidor
esp_http_client_config_t config = {
    .url = "http://192.168.1.69:500/iniciar",
    .method = HTTP_METHOD_GET,
    .timeout_ms = 10000,
};
esp_http_client_handle_t cliente = esp_http_client_init(&config);
esp_http_client_set_header(cliente, "X-Server-ID", "server1");
esp_err_t err = esp_http_client_perform(cliente);
if (err != ESP_OK) {
    ESP_LOGE("app_main", "HTTP request failed: %s", esp_err_to_name(err));
    esp_http_client_cleanup(cliente);
    return;
}
char *response = (char *)malloc(esp_http_client_get_content_length(cliente) + 1);
esp_http_client_read_response(cliente, response, esp_http_client_get_content_length(cliente));
response[esp_http_client_get_content_length(cliente)] = '\0';
ESP_LOGI("app_main", "HTTP response: %s", response);
free(response);
esp_http_client_cleanup(cliente);

// Enviar mensaje

const char *message = "Hola, servidor!";
cJSON *json = cJSON_CreateObject();
cJSON_AddStringToObject(json, "message", message);
char *payload = cJSON_Print(json);
cJSON_Delete(json);
config.url = "http://192.168.1.69:500/enviarMSG";
config.method = HTTP_METHOD_POST;
esp_http_client_set_header(cliente, "X-Server-ID", "server1");
esp_http_client_set_post_field(cliente,payload,strlen(payload));


err = esp_http_client_perform(cliente);
if (err != ESP_OK) {
    ESP_LOGE("app_main", "HTTP request failed: %s", esp_err_to_name(err));
    esp_http_client_cleanup(cliente);
    free(payload);
    return;
}
response = (char *)malloc(esp_http_client_get_content_length(cliente) + 1);
esp_http_client_read_response(cliente, response, esp_http_client_get_content_length(cliente));
response[esp_http_client_get_content_length(cliente)] = '\0';
ESP_LOGI("app_main", "HTTP response: %s", response);
free(response);
esp_http_client_cleanup(cliente);
free(payload);

// Obtener mensajes
config.url = "http://192.168.1.69:500/mensajes";
config.method = HTTP_METHOD_GET;
esp_http_client_set_header(cliente, "X-Server-ID", "server1");

cliente = esp_http_client_init(&config);
err = esp_http_client_perform(cliente);
if (err != ESP_OK) {
    ESP_LOGE("app_main", "HTTP request failed: %s", esp_err_to_name(err));
    esp_http_client_cleanup(cliente);
    return;
}
response = (char *)malloc(esp_http_client_get_content_length(cliente) + 1);
esp_http_client_read_response(cliente, response, esp_http_client_get_content_length(cliente));
response[esp_http_client_get_content_length(cliente)] = '\0';
ESP_LOGI("app_main", "HTTP response: %s", response);
free(response);
esp_http_client_cleanup(cliente);
get_messages();
}
