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
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <psa/crypto_builtin_primitives.h>
#include <mbedtls/ecdh.h>
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
void evaluar(psa_status_t estado)
{
    if (estado == PSA_SUCCESS)
    {
        printf("PSA_SUCCESS1\n");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE \n");
    }

    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED \n");
    }

    else if (estado == PSA_ERROR_ALREADY_EXISTS)
    {
        printf("PSA_ERROR_ALREADY_EXISTS \n");
    }

    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED \n");
    }
    // export key
    else if (estado == PSA_SUCCESS)
    {
        printf("GENERAdo \n");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("Iniciar \n");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("llave no valida \n");
    }
    else if (estado == PSA_ERROR_BUFFER_TOO_SMALL)
    {
        printf("buffer pequeño \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("no clave par \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("no soportado  \n");
    }
    // Acuerdo de secreto
    else if (estado == PSA_SUCCESS)
    {
        printf("GENERACION HECHA");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("iniciar  \n");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("no valido \n");
    }
    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED  \n");
    }
    else if (estado == PSA_ERROR_BUFFER_TOO_SMALL)
    {
        printf("PSA_ERROR_BUFFER_TOO_SMALL  \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT  \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED  \n");
    }
    // SETUP DERIVATION
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED \n");
    }
    // DERIVADA

    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("PSA_ERROR_INVALID_HANDLE");
    }
    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("=PSA_ERROR_NOT_SUPPORTED");
    }
    else if (estado == PSA_ERROR_DATA_INVALID)
    {
        printf("PSA_ERROR_DATA_INVALID");
    }
    else if (estado == PSA_ERROR_INSUFFICIENT_MEMORY)
    {
        printf("PSA_ERROR_DATA_INVALID");
    }
}
void stringToHex(const char *str)
{
    while (*str)
    {
        printf("%02x", *str);
        str++;
    }
    printf("\n");
}
unsigned char hexToByte(const char *hex)
{
    unsigned char byte = 0;

    for (int i = 0; i < 2; i++)
    {
        char c = hex[i];
        byte = byte * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
    }

    return byte;
}

uint8_t* calculateHash(const char* input) {
    size_t inputLength = strlen(input); // Longitud de los datos de entrada
    uint8_t hash[PSA_HASH_MAX_SIZE]; // Buffer para almacenar el hash resultante // Buffer para almacenar el hash resultante
    size_t hashLength; // Variable para almacenar la longitud del hash resultante

    // Calcular el hash utilizando el algoritmo deseado
    psa_algorithm_t algorithm = PSA_ALG_SHA_256; // Ejemplo con el algoritmo SHA-256
    

    
        // Reservar memoria para el buffer del hash
        
        

        // Calcular el hash nuevamente para obtener el resultado
        psa_status_t status = psa_hash_compute(algorithm, (const uint8_t*)input, inputLength, hash, sizeof(hash), &hashLength);
        if (status != PSA_SUCCESS) {
            // Error al calcular el hash
            printf("Error al calcular el hash1: \n");
            free(hash);
            return NULL;
        }
    

    return hash;
}

char* generar_hash(const uint8_t* clave, size_t clave_len, const uint8_t* info, size_t info_len, const uint8_t* salt, size_t salt_len) {
    // Crear el contexto MD de mbedtls
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    // Configurar el hash SHA256
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, md_info, 0);


    size_t total_len = clave_len + info_len + salt_len;

    // Crear un búfer temporal para almacenar la concatenación
    uint8_t* concat_data = malloc(total_len);
    memcpy(concat_data, clave, clave_len);
    memcpy(concat_data + clave_len, info, info_len);
    memcpy(concat_data + clave_len + info_len, salt, salt_len);

    // Actualizar el hash con los datos concatenados
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, concat_data, total_len);
    // Actualizar el hash con los datos a hashear
    /*mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, clave, clave_len);
    
    mbedtls_md_update(&ctx, info, info_len);
    mbedtls_md_update(&ctx, salt, salt_len);*/

    // Obtener el hash resultante
    uint8_t hash_resultante[32];
    mbedtls_md_finish(&ctx, hash_resultante);

    // Crear una cadena de caracteres hexadecimal para almacenar el hash
    char* hash_hex = malloc(65); // 32 bytes (256 bits) + 1 byte para el terminador nulo

    // Convertir el hash resultante a una cadena de caracteres hexadecimal
    for (int i = 0; i < mbedtls_md_get_size(md_info); i++) {
        sprintf(&hash_hex[i * 2], "%02x", hash_resultante[i]);
    }

    // Limpiar y liberar recursos
    mbedtls_md_free(&ctx);

    return hash_hex;
}

void convertirStringAByteArray(const char* str, uint8_t* byteArray, size_t maxLength)
{
    size_t strLength = strlen(str);
    size_t copyLength = strLength < maxLength ? strLength : maxLength;
    memcpy(byteArray, str, copyLength);
}


void convertirCadenaABytes(const char* cadena, uint8_t* arregloBytes, size_t longitud)
{
    // Copia los datos de la cadena al arreglo de bytes
    memcpy(arregloBytes, cadena, longitud);
}

void hexToBytes(const char *hex, unsigned char *bytes, size_t num_bytes)
{
    size_t hex_len = strlen(hex);
    size_t copy_len = (hex_len < (2 * num_bytes)) ? hex_len : (2 * num_bytes);

    for (size_t i = 0; i < copy_len; i += 2)
    {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
}
void intToBytes(int num, unsigned char *bytes)
{
    bytes[0] = (num >> 24) & 0xFF; // Obtén el byte más significativo
    bytes[1] = (num >> 16) & 0xFF; // Obtén el segundo byte más significativo
    bytes[2] = (num >> 8) & 0xFF;  // Obtén el tercer byte más significativo
    bytes[3] = num & 0xFF;         // Obtén el byte menos significativo
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
    if (estado != PSA_SUCCESS)
    {
        printf("ERROR");
    }

    psa_key_attributes_t attributes, atributo3,atributo;
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    atributo3 = psa_key_attributes_init();
    psa_set_key_usage_flags(&atributo3, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&atributo3, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&atributo3, PSA_ALG_CTR);
    psa_set_key_type(&atributo3, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&atributo3, 256);

    

    if (psa_get_key_usage_flags(&attributes) != 0)
    {
        printf("OK");
    }
    // char caz[32];
    // char cadena2[32];
    // char cadena1[32];
    // char cadena3[32];
    char cadena4[32];
    char cadena5[32];

    psa_key_handle_t llave_privada_bob, key, llave_derivada, llave_aes;
    uint8_t llave_publica_bob[65];
    uint8_t llave_aesB[33];
    uint8_t llave_alice[65];
    uint8_t compartidaB[32];
    uint8_t bytesesp[32];
    uint8_t bytesesp1[32];
    uint8_t llave_derivadaB[32];
    size_t olenB, olenA;
    uint32_t output_lenB;
    int j = 0;
    int i = 0;
    int value = 99;

    int value2 = 99;

    estado = psa_generate_key(&attributes, &llave_privada_bob);
    evaluar(estado);
    estado = psa_export_public_key(llave_privada_bob, &llave_publica_bob, sizeof(llave_publica_bob), &olenB);
    evaluar(estado);
    /*for (int i = 0; i < sizeof(llave_publica_bob); i++)
    {
        printf("%02X ", llave_publica_bob[i]); // Imprimir cada byte en hexadecimal
    }*/
    printf("\n");
    printf("\n");

    /*for (int i = 0; i < sizeof(llave_publica_bob); i++) {
                            printf("%02hhx ", llave_publica_bob[i]); // Imprimir cada byte en hexadecimal
                            }*/
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
    /**
     * NOTE: All the configuration parameters for http_client must be spefied either in URL or as host and path parameters.
     * If host and path parameters are not set, query parameter will be ignored. In such cases,
     * query parameter should be specified in URL.
     *
     * If URL as well as host and path parameters are specified, values of host and path will be considered.
     */
    esp_http_client_config_t config = {
        .url = "http://192.168.1.102:80/iniciar", // 69:500 pc  114:80 esp
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

    // esp_http_client_handle_t cliente = esp_http_client_init(&config);
    // const char *post_data = "{\"message\":\"value1\"}";
    char clave_publica_hex[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
    char post_data[256];
    for (int i = 0; i < sizeof(llave_publica_bob); i++)
    {
        snprintf(clave_publica_hex + (2 * i), sizeof(clave_publica_hex) - (2 * i), "%02x", llave_publica_bob[i]);
    }
   /* for (int i = 0; i < sizeof(llave_publica_bob); i++)
    {
        printf("%d", llave_publica_bob[i]);
    }*/
    //printf("\n");
    //printf("\n%s", clave_publica_hex);
    ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
    ESP_LOGI(TAG,"CLAVE PUBLICA CLIENTE: %s",clave_publica_hex);
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "message", clave_publica_hex);
    char *jsonData = cJSON_PrintUnformatted(jsonObject);
    /*snprintf(post_data, sizeof(post_data), "{\"message\":\"%s\"}", clave_publica_hex);
    printf("\n%s",post_data);
*/

    esp_http_client_set_url(client, "http://192.168.1.102:80/enviarMSG");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "X-Server-ID", "esp1");
    esp_http_client_set_header(client, "Content-Type", "application/json");

    // err=esp_http_client_set_post_field(client, clave_publica_hex, strlen(clave_publica_hex));
    // client->post_data=clave_publica_hex;
    err = esp_http_client_set_post_field(client, jsonData, strlen(jsonData));
    // err=esp_http_client_set_post_field(client,clave_publica_hex,strlen(clave_publica_hex));
    ESP_LOGE(TAG, " %s", esp_err_to_name(err));
    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    // GET mensajes
    /*attributes2 = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes2, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&attributes2, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes2, PSA_ALG_ECDH);
    psa_set_key_type(&attributes2, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes2, 257);
    attributes3 = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes3, PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&attributes3, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes3, PSA_ALG_ECDH);
    psa_set_key_type(&attributes3, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes3, 256);
    if (psa_get_key_usage_flags(&attributes3) != 0)
    {
        printf("OK");
    }
*/
    esp_http_client_handle_t cliente = esp_http_client_init(&config);
    esp_http_client_set_url(cliente, "http://192.168.1.102:80/mensajes");
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
       // printf("%s", local_response_buffer);
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
                            uint8_t byte_array[65];
                            attributes = psa_key_attributes_init();
                            // psa_set_key_usage_flags(&attributes3, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_DERIVE|PSA_KEY_USAGE_DECRYPT|PSA_KEY_USAGE_ENCRYPT );
                            /*psa_set_key_lifetime(&attributes3, PSA_KEY_LIFETIME_PERSISTENT);
                            psa_set_key_algorithm(&attributes3, PSA_ALG_ECDH);
                            psa_set_key_type(&attributes3, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
                            psa_set_key_id(&attributes3, PSA_KEY_ID_USER_MIN);
                            psa_set_key_bits(&attributes3, 256);*/
                            /*if (psa_get_key_usage_flags(&attributes) != 0)
                            {
                                printf("OK");
                            }*/
                            ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
                            ESP_LOGI(TAG, "CLAVE PUBLICA SERVIDOR: %s", clavep);
                            ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
                            //printf("%s \n", clavep);
                            size_t hex_len = strlen(clavep);
                            // stringToHex(clavep);
                            size_t byte_len = hex_len / 2;
                            size_t *bytes = (size_t *)malloc(byte_len);
                            if (bytes == NULL)
                            {
                                printf("Error de asignación de memoria\n");
                            }
                            hexToBytes(clavep, llave_alice, byte_len);
                            for (size_t i = 0; i < byte_len; i++)
                            {
                                printf("%d ", llave_alice[i]);
                            }
                            //printf("\n");
                           // ESP_LOGE(TAG, "SEPARADOR");
                            //printf("\n");
                           /* for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                printf("%02X ", llave_alice[i]); // Imprimir cada byte en hexadecimal
                            }*/
                            //printf("\n");
                            for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                snprintf(clavep + (2 * i), sizeof(clavep) - (2 * i), "%02hhx", llave_alice[i]);
                                // Imprimir cada byte en hexadecimal
                            }
                            //printf("\n");
                            /*for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                printf("%02hhx ", llave_alice[i]); // Imprimir cada byte en hexadecimal
                            }*/

                            estado = psa_raw_key_agreement(PSA_ALG_ECDH, llave_privada_bob, &llave_alice, sizeof(llave_alice), compartidaB, sizeof(compartidaB), &output_lenB);
                            printf("\n");
                            evaluar(estado);
                            free(bytes);
                            //printf("\n");
                            //printf("%d", sizeof(output_lenB));
                            //printf("\n");

                            //printf("%d", sizeof(compartidaB));
                            /*printf("\n");
                            printf("Bytes Compartida ESP: ");
                            for (int i = 0; i < sizeof(compartidaB); i++)
                            {
                                printf("%02x ", compartidaB[i]);
                                bytesesp[i] = compartidaB[i]; // Imprimir cada byte en hexadecimal
                            }
                            printf("\n");
                            for (int i = 0; i < sizeof(cadena2); i++)
                            {
                                sprintf(cadena2 + (i * 2), "%02x", bytesesp[i]);
                            }
                            printf("Cadena 1:%s", cadena2);
                            printf("\n");
                            printf("\n");
                            for (int i = 0; i < sizeof(cadena2); i++)
                            {
                                sprintf(cadena2 + (i * 2), "%02x", compartidaB[i]);
                            }
                            printf("%s", cadena2);
                            printf("\n");*/
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
            else{
                cJSON *public_key_alice = cJSON_GetObjectItem(json, "public_key_alice");
                if (cJSON_IsString(public_key_alice))
                        {
                            const char *clavep = cJSON_GetStringValue(public_key_alice);
                            uint8_t byte_array[65];
                            attributes = psa_key_attributes_init();
                            // psa_set_key_usage_flags(&attributes3, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_DERIVE|PSA_KEY_USAGE_DECRYPT|PSA_KEY_USAGE_ENCRYPT );
                            /*psa_set_key_lifetime(&attributes3, PSA_KEY_LIFETIME_PERSISTENT);
                            psa_set_key_algorithm(&attributes3, PSA_ALG_ECDH);
                            psa_set_key_type(&attributes3, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
                            psa_set_key_id(&attributes3, PSA_KEY_ID_USER_MIN);
                            psa_set_key_bits(&attributes3, 256);*/
                            
                            ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
                            ESP_LOGI(TAG, "CLAVE PUBLICA SERVIDOR: %s", clavep);
                            ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
                            size_t hex_len = strlen(clavep);
                            // stringToHex(clavep);
                            size_t byte_len = hex_len / 2;
                            size_t *bytes = (size_t *)malloc(byte_len);
                            if (bytes == NULL)
                            {
                                printf("Error de asignación de memoria\n");
                            }
                            hexToBytes(clavep, llave_alice, byte_len);
                            /*for (size_t i = 0; i < byte_len; i++)
                            {
                                printf("%d ", llave_alice[i]);
                            }*/
                            /*printf("\n");
                            ESP_LOGE(TAG, "SEPARADOR");
                            printf("\n");
                            for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                printf("%02X ", llave_alice[i]); // Imprimir cada byte en hexadecimal
                            }
                            printf("\n");
                            for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                snprintf(clavep + (2 * i), sizeof(clavep) - (2 * i), "%02hhx", llave_alice[i]);
                                // Imprimir cada byte en hexadecimal
                            }
                            printf("\n");
                            for (int i = 0; i < sizeof(llave_alice); i++)
                            {
                                printf("%02hhx ", llave_alice[i]); // Imprimir cada byte en hexadecimal
                            }*/

                            estado = psa_raw_key_agreement(PSA_ALG_ECDH, llave_privada_bob, &llave_alice, sizeof(llave_alice), compartidaB, sizeof(compartidaB), &output_lenB);
                            printf("\n");
                            evaluar(estado);
                            free(bytes);
                            /*printf("\n");
                            printf("%d", sizeof(output_lenB));
                            printf("\n");

                            printf("%d", sizeof(compartidaB));
                            printf("\n");
                            printf("Bytes Compartida ESP: ");
                            for (int i = 0; i < sizeof(compartidaB); i++)
                            {
                                printf("%02x ", compartidaB[i]);
                                bytesesp[i] = compartidaB[i]; // Imprimir cada byte en hexadecimal
                            }
                            printf("\n");
                            for (int i = 0; i < sizeof(cadena2); i++)
                            {
                                sprintf(cadena2 + (i * 2), "%02x", bytesesp[i]);
                            }
                            printf("Cadena 1:%s", cadena2);
                            printf("\n");
                            printf("\n");
                            for (int i = 0; i < sizeof(cadena2); i++)
                            {
                                sprintf(cadena2 + (i * 2), "%02x", compartidaB[i]);
                            }
                            printf("%s", cadena2);
                            printf("\n");*/
                        }

            }
        }
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    // POST Compartida

    // esp_http_client_handle_t cliente = esp_http_client_init(&config);
    // const char *post_data = "{\"message\":\"value1\"}";
    char clave_publica_hex2[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
    char post_data2[256];
    for (int i = 0; i < sizeof(compartidaB); i++)
    {
        snprintf(clave_publica_hex2 + (2 * i), sizeof(clave_publica_hex2) - (2 * i), "%02x", compartidaB[i]);
    }
    /*for (int i = 0; i < sizeof(compartidaB); i++)
    {
        printf("%d", compartidaB[i]);
    }*/
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
    ESP_LOGI(TAG, "CLAVE COMPARTIDA CLIENTE: %s", clave_publica_hex2);
    ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
    /*printf("\n");
    printf("\nCOMPARTIDA ;%s", clave_publica_hex2);*/
    cJSON *jsonObject2 = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject2, "compartidaB", clave_publica_hex2);
    char *jsonData2 = cJSON_PrintUnformatted(jsonObject2);
    /*snprintf(post_data, sizeof(post_data), "{\"message\":\"%s\"}", clave_publica_hex);
    printf("\n%s",post_data);
*/

    esp_http_client_set_url(client, "http://192.168.1.102:80/compartida");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "X-Server-ID", "esp1");
    esp_http_client_set_header(client, "Content-Type", "application/json");
    // err=esp_http_client_set_post_field(client, clave_publica_hex, strlen(clave_publica_hex));
    err = esp_http_client_set_post_field(client, jsonData2, strlen(jsonData2));
    ESP_LOGE(TAG, " %s", esp_err_to_name(err));
    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    // GET veryfy
    esp_http_client_handle_t cliente2 = esp_http_client_init(&config);
    esp_http_client_set_url(cliente2, "http://192.168.1.102:80/verificacion");
    esp_http_client_set_header(cliente2, "X-Server-ID", "esp1");
    // esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_method(cliente2, HTTP_METHOD_GET);
    err = esp_http_client_perform(cliente2);
    int vp = 0;

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
        //printf("%s", local_response_buffer);
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
                cJSON *valor = cJSON_GetObjectItem(esp1, "valor");
                if (valor != NULL)
                {
                    if (cJSON_IsNumber(valor))
                    {
                        value = cJSON_GetNumberValue(valor);
                        if (value == 0)
                        {
                            ESP_LOGI(TAG, "LOGRADO");
                        }
                        else
                        {
                            ESP_LOGE(TAG, "ERRORRRRRR");
                        }
                    }
                    else
                    {
                        ESP_LOGE(TAG, "ERRORRRRRR2");
                    }
                }
                else
                {
                    ESP_LOGE(TAG, "ERRORRRRRR3");
                }
            }
            else
            {
                cJSON *valor = cJSON_GetObjectItem(json, "valor");
                if (cJSON_IsNumber(valor))
                    {
                        value = cJSON_GetNumberValue(valor);
                        if (value == 0)
                        {
                            ESP_LOGI(TAG, "LOGRADO");
                        }
                        else
                        {
                            ESP_LOGE(TAG, "ERRORRRRRR");
                        }
                    }

            }
        }
    }
    // POST DERIVADA
    psa_key_derivation_operation_t operacion;
    operacion = psa_key_derivation_operation_init();
    uint8_t vuelta = 0;
    char * lol="aaaa";
    uint8_t* bytes=(uint8_t*)lol;
    const char* cadena = "isma_crypto_send";
    int len =strlen(cadena);
    int len2=strlen(lol);
    //printf("%d",len);
    //printf("\n");
    //len=len*2;
    //printf("%d",len);
    uint8_t bufff[len];
    uint8_t bufff2[len2];
    //printf("%d",sizeof(bufff));
    printf("\n");
    /*while (cadena[i]!='\0')
    {
        bufff[i]=(uint8_t)cadena[i];
        printf("%d",bufff[i]);
    }
    printf("\n");*/
    
    for (size_t i = 0; i < len; i++)
    {
        bufff[i]=(uint8_t)cadena[i];
        //printf("%02x",bufff[i]);
    }
    //printf("\n");  
    for (size_t i = 0; i < len2; i++)
    {
        bufff2[i]=(uint8_t)lol[i];
       //printf("%02x",bufff2[i]);
    }  
    
    
    
    const uint8_t arregloBytes[50];
    uint8_t myArray[32] = {0};
    uint8_t hashes[50];
    uint8_t olen_lenV;
    psa_key_handle_t comp,comp2;
    const uint8_t* input = (const uint8_t*)"HOLA";

    //printf("\n");
    //printf("\n");
   // printf("\n");
    //printf("\n");
   // printf("Bytes; ");
    /*for (size_t i = 0; i < sizeof(bytes); i++)
    {
        printf("%02x",bytes[i]);
    }
    //printf("\n");
   // printf("INPUT; ");
    for (size_t i = 0; i < sizeof(bytes); i++)
    {
        printf("%02x",input[i]);
    }
    printf("\n");*/
   /* printf("Compartida; ");
    for (size_t i = 0; i < sizeof(compartidaB); i++)
    {
        printf("%02x",compartidaB[i]);
    }*/
    //printf("\n");
    estado = psa_import_key(&atributo3, compartidaB, sizeof(compartidaB), &comp);
    evaluar(estado);
    estado = psa_key_derivation_setup(&operacion,  PSA_ALG_HKDF(PSA_ALG_SHA_256));

    evaluar(estado);
    estado = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_SALT, bufff2, sizeof(bufff2));
    
    evaluar(estado);
   
    estado=psa_key_derivation_input_bytes(&operacion,PSA_KEY_DERIVATION_INPUT_SECRET,compartidaB,sizeof(compartidaB));
    evaluar(estado);
    
    estado = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_INFO, bufff, sizeof(bufff));
    evaluar(estado);

    printf("break \n");
    estado = psa_key_derivation_output_key(&atributo3, &operacion, &llave_derivada);
    evaluar(estado);
    estado = psa_key_derivation_output_bytes(&operacion, &llave_derivadaB, sizeof(llave_derivadaB));
    evaluar(estado);
    estado = psa_key_derivation_abort(&operacion);
    // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
    char clave_publica_hex3[135]; 
    char post_data3[256];
    for (int i = 0; i < sizeof(llave_derivadaB); i++)
    {
        snprintf(clave_publica_hex3 + (2 * i), sizeof(clave_publica_hex3) - (2 * i), "%02x", llave_derivadaB[i]);
    }
    
    for (int i = 0; i < sizeof(llave_derivadaB); i++)
    {
        printf("%02x", llave_derivadaB[i]);
    }
    printf("\n");
    ESP_LOGE(TAG, "------------------------------------------------------------------------");
    ESP_LOGI(TAG,"CLAVE DERIVADA: %s",clave_publica_hex3);
    ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
    
    
    //printf("\nDerivada1: %s", clave_publica_hex3);
    cJSON *jsonObject3 = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject3, "DerivadaB", clave_publica_hex3);
    char *jsonData3 = cJSON_PrintUnformatted(jsonObject3);
    
    /*snprintf(post_data, sizeof(post_data), "{\"message\":\"%s\"}", clave_publica_hex);
    printf("\n%s",post_data);
*/

    esp_http_client_set_url(client, "http://192.168.1.102:80/Derivada");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "X-Server-ID", "esp1");
    esp_http_client_set_header(client, "Content-Type", "application/json");
    // err=esp_http_client_set_post_field(client, clave_publica_hex, strlen(clave_publica_hex));
    err = esp_http_client_set_post_field(client, jsonData3, strlen(jsonData3));
    ESP_LOGE(TAG, " %s", esp_err_to_name(err));
    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }
    vuelta++;

    // Get verify

    esp_http_client_set_url(cliente2, "http://192.168.1.102:80/verificacion2");
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
        psa_cipher_operation_t operation;
        operation = psa_cipher_operation_init();
        uint8_t ivs[33];
        uint8_t mensaje = 54;
        size_t olenC;
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
        //printf("%s", local_response_buffer);
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
                cJSON *valor2 = cJSON_GetObjectItem(esp1, "valor2");
                if (valor2 != NULL)
                {
                    if (cJSON_IsNumber(valor2))
                    {
                        value2 = cJSON_GetNumberValue(valor2);
                        if (value2 == 0)
                        {
                            ESP_LOGI(TAG, "LOGRADO");
                        }
                    }
                }
            }
        }
    }
    vuelta++;
    // CIFRAR
    psa_cipher_operation_t cifrado, cifrado2;
    
    cifrado = psa_cipher_operation_init();
    cifrado2 = psa_cipher_operation_init();
    uint8_t iv_s[PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CTR)];
    memset(iv_s, 0, sizeof(iv_s));
    uint8_t mensaje[32];
    uint8_t descifrado[33];
    srand(time(NULL));
    for (size_t i = 0; i < sizeof(mensaje); i++)
    {
        mensaje[i] = (uint8_t)rand();
    }
    printf("Números aleatorios:\n");
    for (size_t i = 0; i < sizeof(mensaje); i++)
    {
        printf("%u ", mensaje[i]);
    }
    printf("\n");
    size_t olenC, olenD;
    estado = psa_import_key(&atributo3, llave_derivadaB, sizeof(llave_derivadaB), &comp2);
    evaluar(estado);
    estado = psa_cipher_encrypt_setup(&cifrado, comp2, PSA_ALG_CTR);
    evaluar(estado);
    estado = psa_cipher_decrypt_setup(&cifrado2, comp2, PSA_ALG_CTR);
    evaluar(estado);
    // estado=psa_cipher_set_iv(&cifrado,&iv_s,output_lenC);
    /*estado = psa_cipher_generate_iv(&cifrado, &iv_s, PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR), &output_lenC);
    evaluar(estado);*/
    estado = psa_cipher_set_iv(&cifrado, &iv_s, 16);
    evaluar(estado);
    estado = psa_cipher_set_iv(&cifrado2, &iv_s, 16);
    evaluar(estado);
    // printf("%ld",output_lenC);
    estado = psa_cipher_update(&cifrado, mensaje, sizeof(mensaje), &llave_aesB, sizeof(llave_aesB), &olenD);

    estado = psa_cipher_finish(&cifrado, &llave_aesB, sizeof(llave_aesB), &olenD);
    evaluar(estado);
    //------------------------------------------------------------------------------------------------------

    estado = psa_cipher_update(&cifrado2, llave_aesB, sizeof(llave_aesB), &descifrado, sizeof(descifrado), &output_lenB);
    evaluar(estado);
    estado = psa_cipher_finish(&cifrado2, &descifrado, sizeof(descifrado), &output_lenB);
    evaluar(estado);

    char clave_publica_hex4[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

    for (int i = 0; i < sizeof(llave_aesB); i++)
    {
        snprintf(clave_publica_hex4 + (2 * i), sizeof(clave_publica_hex4) - (2 * i), "%02x", llave_aesB[i]);
    }
    for (int i = 0; i < sizeof(llave_aesB); i++)
    {
        // printf("%d", llave_aesB[i]);
    }
    
    ESP_LOGE(TAG, "------------------------------------------------------------------------");
    ESP_LOGI(TAG,"MENSAJE CIFRADO CLIENTE: %s",clave_publica_hex4);
    ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
  //  printf("\nCIfrado:%s", clave_publica_hex4);

    char clave_publica_hex99[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

    for (int i = 0; i < sizeof(descifrado); i++)
    {
        snprintf(clave_publica_hex99 + (2 * i), sizeof(clave_publica_hex99) - (2 * i), "%02x", descifrado[i]);
    }
    for (int i = 0; i < sizeof(descifrado); i++)
    {
        // printf("%d", descifrado[i]);
    }
    char clave_publica_hex6[PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CTR)]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

    /*for (int i = 0; i < PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CTR); i++)
    {
        snprintf(clave_publica_hex6 + (2 * i), sizeof(clave_publica_hex6) - (2 * i), "%02x", iv_s[i]);
    }
    for (int i = 0; i < sizeof(iv_s); i++)
    {
        // printf("%d", descifrado[i]);
    }*/
   /* printf("\n");
    for (int i = 0; i < sizeof(iv_s); i++)
    {
        printf("%02x", iv_s[i]);
    }
    printf("\n");
    printf("\nIV:%s", clave_publica_hex6);*/

    printf("\n");
    ESP_LOGE(TAG, "------------------------------------------------------------------------");
    ESP_LOGI(TAG,"MENSAJE DESCIFRADO CLIENTE: %s",clave_publica_hex99);
    ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
    //printf("\nDescifrado:%s", clave_publica_hex5);

    cJSON *jsonObject4 = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject4, "msg", clave_publica_hex4);

    char *jsonData4 = cJSON_PrintUnformatted(jsonObject4);

    esp_http_client_set_url(client, "http://192.168.1.102:80/cifrado");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "X-Server-ID", "esp1");
    esp_http_client_set_header(client, "Content-Type", "application/json");
    // err=esp_http_client_set_post_field(client, clave_publica_hex, strlen(clave_publica_hex));
    err = esp_http_client_set_post_field(client, jsonData4, strlen(jsonData4));
    ESP_LOGE(TAG, " %s", esp_err_to_name(err));
    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    // DESCIFRAR
    esp_http_client_set_url(cliente2, "http://192.168.1.102:80/descifrado");
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
        uint8_t msg2[32];
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
        //printf("%s", local_response_buffer);
        cJSON *json = cJSON_Parse(local_response_buffer);

        cJSON *cifrado = cJSON_GetObjectItem(json, "cifrado");

        /* code */
        psa_key_handle_t comp3;
        char cmp[150];
        for (int i = 0; i < sizeof(llave_derivadaB); i++)
    {
        snprintf(cmp + (2 * i), sizeof(cmp) - (2 * i), "%02x", llave_derivadaB[i]);
    }
    
        uint8_t iv_s2[PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CTR)];
        memset(iv_s2, 0, sizeof(iv_s));
        char *valor77 = cJSON_GetStringValue(cifrado);
       // printf(" %s\n", valor77);
        //printf(" %s\n",cmp );
        uint8_t descifrado2[32];
        uint8_t usar[65];
        //hexToBytes(cmp,usar,sizeof(usar));
        estado = psa_import_key(&atributo3, llave_derivadaB, sizeof(llave_derivadaB), &comp3);
        evaluar(estado);
        ESP_LOGE(TAG, "------------------------------------------------------------------------");
        ESP_LOGI(TAG,"MENSAJE CIFRADO SERVIDOR: %s",valor77);
        ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
        //printf("\n%s\n",valor77);
        hexToBytes(valor77, msg2, sizeof(msg2));
        estado = psa_cipher_decrypt_setup(&cifrado2, comp3, PSA_ALG_CTR);
        evaluar(estado);
        estado = psa_cipher_set_iv(&cifrado2, &iv_s2, 16);
        evaluar(estado);
        estado = psa_cipher_update(&cifrado2, msg2, sizeof(msg2), descifrado2, sizeof(descifrado2), &output_lenB);
        evaluar(estado);
        estado = psa_cipher_finish(&cifrado2, msg2, sizeof(msg2), &output_lenB);
        evaluar(estado);
        char clave_publica_hex11[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

        for (int i = 0; i < sizeof(descifrado2); i++)
        {
            snprintf(clave_publica_hex11 + (2 * i), sizeof(clave_publica_hex11) - (2 * i), "%02x", descifrado2[i]);
        }
        printf("\n");
        ESP_LOGE(TAG, "------------------------------------------------------------------------");
        ESP_LOGI(TAG,"MENSAJE DESCIFRADO SERVIDOR: %s",clave_publica_hex11);
        ESP_LOGE(TAG, "\n------------------------------------------------------------------------\n");
        //printf("\nDescifrado2:%s", clave_publica_hex11);
    
}

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

    xTaskCreate(&http_test_task, "http_test_task", 16384, NULL, 5, NULL);
}
