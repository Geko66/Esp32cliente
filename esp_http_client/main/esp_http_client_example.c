/* ESP HTTP Client Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif

#include "esp_http_client.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048
static const char *TAG = "HTTP_CLIENT";

/* Root cert for howsmyssl.com, taken from howsmyssl_com_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const char howsmyssl_com_root_cert_pem_start[] asm("_binary_howsmyssl_com_root_cert_pem_start");
extern const char howsmyssl_com_root_cert_pem_end[] asm("_binary_howsmyssl_com_root_cert_pem_end");

extern const char postman_root_cert_pem_start[] asm("_binary_postman_root_cert_pem_start");
extern const char postman_root_cert_pem_end[] asm("_binary_postman_root_cert_pem_end");
void evaluar(psa_status_t estado){
     if (estado==PSA_SUCCESS){
        printf("PSA_SUCCESS1\n");
       
    }
    else if(estado==PSA_ERROR_BAD_STATE){
        printf("PSA_ERROR_BAD_STATE \n");
    }

      else if(estado==PSA_ERROR_NOT_PERMITTED){
        printf("PSA_ERROR_NOT_PERMITTED \n");
    }

    else if(estado==PSA_ERROR_ALREADY_EXISTS){
        printf("PSA_ERROR_ALREADY_EXISTS \n");
    }

    else if(estado==PSA_ERROR_INVALID_ARGUMENT){
        printf("PSA_ERROR_INVALID_ARGUMENT \n");
    }
    else if(estado==PSA_ERROR_NOT_SUPPORTED){
        printf("PSA_ERROR_NOT_SUPPORTED \n");
    }
    // export key
    else  if (estado==PSA_SUCCESS){
        printf("GENERAdo \n");
    }
    else if(estado==PSA_ERROR_BAD_STATE){
        printf("Iniciar \n");
    }
    else if(estado==PSA_ERROR_INVALID_HANDLE){
        printf("llave no valida \n");
    }
     else if(estado==PSA_ERROR_BUFFER_TOO_SMALL){
        printf("buffer pequeño \n");
    }
    else if(estado==PSA_ERROR_INVALID_ARGUMENT){
        printf("no clave par \n");
    }
else if(estado==PSA_ERROR_NOT_SUPPORTED){
        printf("no soportado  \n");
    }
//Acuerdo de secreto
    else if (estado==PSA_SUCCESS){
        printf("GENERACION HECHA");
    }
    else if(estado==PSA_ERROR_BAD_STATE){
        printf("iniciar  \n");
    }
    else if(estado==PSA_ERROR_INVALID_HANDLE){
        printf("no valido \n");
    }
     else if(estado==PSA_ERROR_NOT_PERMITTED){
        printf("PSA_ERROR_NOT_PERMITTED  \n");
    }
     else if(estado==PSA_ERROR_BUFFER_TOO_SMALL){
        printf("PSA_ERROR_BUFFER_TOO_SMALL  \n");
    }
     else if(estado==PSA_ERROR_INVALID_ARGUMENT){
        printf("PSA_ERROR_INVALID_ARGUMENT  \n");
    }
     else if(estado==PSA_ERROR_NOT_SUPPORTED){
        printf("PSA_ERROR_NOT_SUPPORTED  \n");
    }
    //SETUP DERIVATION
     else if(estado==PSA_ERROR_BAD_STATE){
            printf("PSA_ERROR_BAD_STATE \n");
        }
        else if(estado==PSA_ERROR_INVALID_ARGUMENT){
            printf("PSA_ERROR_INVALID_ARGUMENT \n");
        }
        else if(estado==PSA_ERROR_NOT_SUPPORTED){
            printf("PSA_ERROR_NOT_SUPPORTED \n");
        }
        //DERIVADA
       
    
    else if(estado==PSA_ERROR_BAD_STATE){
        printf("PSA_ERROR_BAD_STATE");
    }
    else if(estado==PSA_ERROR_INVALID_HANDLE){
        printf("PSA_ERROR_INVALID_HANDLE");
    }
        else if(estado==PSA_ERROR_NOT_PERMITTED){
        printf("PSA_ERROR_NOT_PERMITTED");
    }
        else if(estado==PSA_ERROR_INVALID_ARGUMENT){
        printf("PSA_ERROR_INVALID_ARGUMENT");
    }
        else if(estado==PSA_ERROR_NOT_SUPPORTED){
        printf("=PSA_ERROR_NOT_SUPPORTED");
    }
        else if(estado==PSA_ERROR_DATA_INVALID){
        printf("PSA_ERROR_DATA_INVALID");
    }
      else if(estado==PSA_ERROR_INSUFFICIENT_MEMORY){
        printf("PSA_ERROR_DATA_INVALID");
    }

}


esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer; // Buffer to store response of http request from event handler
    static int output_len;      // Stores number of bytes read
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        /*
         *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
         *  However, event handler can also be used in case chunked encoding is used.
         */
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            // If user_data buffer is configured, copy the response into the buffer
            if (evt->user_data)
            {
                memcpy(evt->user_data + output_len, evt->data, evt->data_len);
            }
            else
            {
                if (output_buffer == NULL)
                {
                    output_buffer = (char *)malloc(esp_http_client_get_content_length(evt->client));
                    output_len = 0;
                    if (output_buffer == NULL)
                    {
                        ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                        return ESP_FAIL;
                    }
                }
                memcpy(output_buffer + output_len, evt->data, evt->data_len);
            }
            output_len += evt->data_len;
        }

        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        if (output_buffer != NULL)
        {
            // Response is accumulated in output_buffer. Uncomment the below line to print the accumulated response
            // ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        if (output_buffer != NULL)
        {
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
        esp_http_client_set_header(evt->client, "From", "user@example.com");
        esp_http_client_set_header(evt->client, "Accept", "text/html");
        esp_http_client_set_redirection(evt->client);
        break;
    }
    return ESP_OK;
}

static void http_rest_with_url(void)
{
    psa_status_t estado;
    estado = psa_crypto_init();
     if(estado!=PSA_SUCCESS){
        printf("ERROR");
        }
    psa_key_attributes_t attributes;
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes,PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes,256);
    if (psa_get_key_usage_flags(&attributes)!=0)
    {
    printf("OK");
    }
    psa_key_handle_t llave_privada_bob;
    uint8_t llave_publica_bob[65];
    uint8_t compartidaB[33];
    size_t olenB;
    
    estado=psa_generate_key(&attributes,&llave_privada_bob);
    evaluar(estado);
    estado= psa_export_public_key(llave_privada_bob,&llave_publica_bob,sizeof(llave_publica_bob),&olenB);
    evaluar(estado);


    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
    /**
     * NOTE: All the configuration parameters for http_client must be spefied either in URL or as host and path parameters.
     * If host and path parameters are not set, query parameter will be ignored. In such cases,
     * query parameter should be specified in URL.
     *
     * If URL as well as host and path parameters are specified, values of host and path will be considered.
     */
    esp_http_client_config_t config = {
        .url = "http://192.168.1.69:500/iniciar",
        .method = HTTP_METHOD_GET,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer, // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "X-Server-ID", "esp1");

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));

    // POST


     //esp_http_client_handle_t cliente = esp_http_client_init(&config);
     //const char *post_data = "{\"message\":\"value1\"}";
    char clave_publica_hex[130];// 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
    char post_data[256]; 
    for (int i = 0; i < sizeof(llave_publica_bob); i++) {
    snprintf(clave_publica_hex + (2 * i), sizeof(clave_publica_hex) - (2 * i), "%02x", llave_publica_bob[i]);
}   
    printf("\n%s",clave_publica_hex);
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject,"message", clave_publica_hex);
    char *jsonData = cJSON_PrintUnformatted(jsonObject);
    /*snprintf(post_data, sizeof(post_data), "{\"message\":\"%s\"}", clave_publica_hex);
    printf("\n%s",post_data);
*/


     esp_http_client_set_url(client, "http://192.168.1.69:500/enviarMSG");
     esp_http_client_set_method(client, HTTP_METHOD_POST);
     esp_http_client_set_header(client, "X-Server-ID", "esp1");
     esp_http_client_set_header(client, "Content-Type", "application/json");
     //err=esp_http_client_set_post_field(client, clave_publica_hex, strlen(clave_publica_hex));
     err=esp_http_client_set_post_field(client,jsonData,strlen(jsonData));
     ESP_LOGE(TAG, " %s", esp_err_to_name(err));
     err = esp_http_client_perform(client);
     if (err == ESP_OK) {
         ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
     } else {
         ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
     }



    // GET mensajes
    esp_http_client_handle_t cliente = esp_http_client_init(&config);
    esp_http_client_set_url(cliente, "http://192.168.1.69:500/mensajes");
    esp_http_client_set_header(cliente, "X-Server-ID", "esp1");
    // esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_method(cliente, HTTP_METHOD_GET);
    err = esp_http_client_perform(cliente);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(cliente),
                 esp_http_client_get_content_length(cliente));

        // Leer los datos de la respuesta HTTP

        int buffer_size = esp_http_client_get_content_length(client) + 1;

        // Leer los datos de la respuesta HTTP en fragmentos más pequeños
        char *buffer = malloc(buffer_size);
        int total_read_len = 0;
        int read_len;
        while ((read_len = esp_http_client_read(client, buffer + total_read_len, buffer_size - total_read_len)) > 0)
        {
            total_read_len += read_len;

            // Comprobar si se ha alcanzado el tamaño máximo del búfer
            if (total_read_len == buffer_size)
            {
                // Aumentar el tamaño del búfer
                buffer_size *= 2;
                buffer = realloc(buffer, buffer_size);
            }
        }

        // Asegurarse de que el búfer esté terminado con un carácter nulo
        buffer[total_read_len] = '\0';
        printf("%s", local_response_buffer);
        cJSON *json = cJSON_Parse(local_response_buffer);

        if (json == NULL)
        {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL)
            {
                ESP_LOGE(TAG, "Error parsing JSON: %s", error_ptr);
            }
            // Manejar el error de análisis del JSON
        }
        else
        {
            cJSON *esp1 = cJSON_GetObjectItem(json, "esp1");
            if (esp1 != NULL)
            {
                // cJSON *messages = cJSON_GetObjectItem(esp1, "messages");
                cJSON *public_key_alice = cJSON_GetObjectItem(esp1, "public_key_alice");

                /*if (messages != NULL)
                {
                    if (cJSON_IsArray(messages))
                    {
                        int messages_count = cJSON_GetArraySize(messages);
                        for (int i = 0; i < messages_count; i++)
                        {
                            cJSON *message = cJSON_GetArrayItem(messages, i);
                            if (cJSON_IsString(message))
                            {
                                const char *message_str = cJSON_GetStringValue(message);
                                ESP_LOGI(TAG, "Message %d: %s", i + 1, message_str);
                            }
                        }
                    }
                }
                else
                    printf("\n hola3");
*/
                if (public_key_alice != NULL)
                {
                    if (cJSON_IsArray(public_key_alice))
                    {
                        const char *cla = cJSON_GetArrayItem(public_key_alice, 0);
                        if (cJSON_IsString(cla))
                        {
                            const char *clavep = cJSON_GetStringValue(cla);
                            ESP_LOGI(TAG, "Public %s", clavep);
                            size_t hex_len = strlen(clavep);
                            size_t byte_len = hex_len / 2;
                            unsigned char *bytes = (unsigned char *)malloc(byte_len);
                            if (bytes == NULL)
                            {
                                printf("Error de asignación de memoria\n");
                            }

                            for (size_t i = 0; i < byte_len; i++)
                            {
                                sscanf(clavep + (2 * i), "%2hhx", &bytes[i]);
                            }

                            printf("Bytes: ");
                            for (size_t i = 0; i < byte_len; i++)
                            {
                                printf("%02x ", bytes[i]);
                            }
                            printf("\n");

                            free(bytes);
                        }

                        else
                            printf("\n hola fallo");
                    }
                }
                else
                    printf("\n hola4");

                cJSON_Delete(json); // Liberar la memoria asignada por cJSON_Parse
                free(buffer);
            }
        }
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
//GET COMPARTIDA
esp_http_client_handle_t cliente2 = esp_http_client_init(&config);
    esp_http_client_set_url(cliente2, "http://192.168.1.69:500/compartida");
    esp_http_client_set_header(cliente2, "X-Server-ID", "esp1");
    // esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_method(cliente2, HTTP_METHOD_GET);
    err = esp_http_client_perform(cliente2);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(cliente2),
                 esp_http_client_get_content_length(cliente2));

        // Leer los datos de la respuesta HTTP

        int buffer_size = esp_http_client_get_content_length(cliente2) + 1;

        // Leer los datos de la respuesta HTTP en fragmentos más pequeños
        char *buffer = malloc(buffer_size);
        int total_read_len = 0;
        int read_len;
        while ((read_len = esp_http_client_read(cliente2, buffer + total_read_len, buffer_size - total_read_len)) > 0)
        {
            total_read_len += read_len;

            // Comprobar si se ha alcanzado el tamaño máximo del búfer
            if (total_read_len == buffer_size)
            {
                // Aumentar el tamaño del búfer
                buffer_size *= 2;
                buffer = realloc(buffer, buffer_size);
            }
        }

        // Asegurarse de que el búfer esté terminado con un carácter nulo
        buffer[total_read_len] = '\0';
        printf("%s", local_response_buffer);
        cJSON *json = cJSON_Parse(local_response_buffer);

        if (json == NULL)
        {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL)
            {
                ESP_LOGE(TAG, "Error parsing JSON: %s", error_ptr);
            }
            // Manejar el error de análisis del JSON
        }
        else
        {
            cJSON *esp1 = cJSON_GetObjectItem(json, "esp1");
            if (esp1 != NULL)
            {
                // cJSON *messages = cJSON_GetObjectItem(esp1, "messages");
                cJSON *compartida = cJSON_GetObjectItem(esp1, "compartida");

                /*if (messages != NULL)
                {
                    if (cJSON_IsArray(messages))
                    {
                        int messages_count = cJSON_GetArraySize(messages);
                        for (int i = 0; i < messages_count; i++)
                        {
                            cJSON *message = cJSON_GetArrayItem(messages, i);
                            if (cJSON_IsString(message))
                            {
                                const char *message_str = cJSON_GetStringValue(message);
                                ESP_LOGI(TAG, "Message %d: %s", i + 1, message_str);
                            }
                        }
                    }
                }
                else
                    printf("\n hola3");
*/
                if (compartida != NULL)
                {
                    if (cJSON_IsArray(compartida))
                    {
                        const char *cla2 = cJSON_GetArrayItem(compartida, 0);
                        if (cJSON_IsString(cla2))
                        {
                            const char *clavep2 = cJSON_GetStringValue(cla2);
                            ESP_LOGI(TAG, "Public %s", clavep2);
                            size_t hex_len2 = strlen(clavep2);
                            size_t byte_len2= hex_len2 / 2;
                            unsigned char *bytes2 = (unsigned char *)malloc(byte_len2);
                            if (bytes2 == NULL)
                            {
                                printf("Error de asignación de memoria\n");
                            }

                            for (size_t i = 0; i < byte_len2; i++)
                            {
                                sscanf(clavep2 + (2 * i), "%2hhx", &bytes2[i]);
                            }

                            printf("Bytes: ");
                            for (size_t i = 0; i < byte_len2; i++)
                            {
                                printf("%02x ", bytes2[i]);
                            }
                            printf("\n");

                            free(bytes2);
                        }

                        else
                            printf("\n hola fallo");
                    }
                }
                else
                    printf("\n hola4");

                cJSON_Delete(json); // Liberar la memoria asignada por cJSON_Parse
                free(buffer);
            }
        }
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }



    /* esp_http_client_set_url(cliente, "http://192.168.1.219:500/mensajes");
     esp_http_client_set_method(cliente, HTTP_METHOD_GET);
     err = esp_http_client_perform(client);
     if (err == ESP_OK) {
         ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
     } else {
         ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
     }
     ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));
     */
    /*
        //PUT
        esp_http_client_set_url(client, "http://httpbin.org/put");
        esp_http_client_set_method(client, HTTP_METHOD_PUT);
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "HTTP PUT Status = %d, content_length = %lld",
                    esp_http_client_get_status_code(client),
                    esp_http_client_get_content_length(client));
        } else {
            ESP_LOGE(TAG, "HTTP PUT request failed: %s", esp_err_to_name(err));
        }

        //PATCH
        esp_http_client_set_url(client, "http://httpbin.org/patch");
        esp_http_client_set_method(client, HTTP_METHOD_PATCH);
        esp_http_client_set_post_field(client, NULL, 0);
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "HTTP PATCH Status = %d, content_length = %lld",
                    esp_http_client_get_status_code(client),
                    esp_http_client_get_content_length(client));
        } else {
            ESP_LOGE(TAG, "HTTP PATCH request failed: %s", esp_err_to_name(err));
        }

        //DELETE
        esp_http_client_set_url(client, "http://httpbin.org/delete");
        esp_http_client_set_method(client, HTTP_METHOD_DELETE);
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "HTTP DELETE Status = %d, content_length = %lld",
                    esp_http_client_get_status_code(client),
                    esp_http_client_get_content_length(client));
        } else {
            ESP_LOGE(TAG, "HTTP DELETE request failed: %s", esp_err_to_name(err));
        }

        //HEAD
        esp_http_client_set_url(client, "http://httpbin.org/get");
        esp_http_client_set_method(client, HTTP_METHOD_HEAD);
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "HTTP HEAD Status = %d, content_length = %lld",
                    esp_http_client_get_status_code(client),
                    esp_http_client_get_content_length(client));
        } else {
            ESP_LOGE(TAG, "HTTP HEAD request failed: %s", esp_err_to_name(err));
        }

        esp_http_client_cleanup(client);
    }
    */
}
static void http_test_task(void *pvParameters)
{

    http_rest_with_url();
    ESP_LOGI(TAG, "Finish http example");
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    ESP_LOGI(TAG, "Connected to AP, begin http example");

    xTaskCreate(&http_test_task, "http_test_task", 8192, NULL, 5, NULL);
}
