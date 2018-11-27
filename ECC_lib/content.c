#include <stdint.h>
void print_content(uint8_t *content,int c_size){
    int i =0;


    while(1){
        if(content[i] != '\0'){
            //printf("content[%d] : %10x\n",i,content[i]);
            printf("%x",content[i]);
        }else{
            break;
        }
        i++;
    }
    printf("\nresult length : [%d]\n",i);
}
void print_parameter(int parameter){
    printf("---------------------\n");
    switch(parameter){
    case 16:
        printf("secp128r1 - [%d] bytes\n",parameter);
        break;
    case 24:
        printf("secp192r1 - [%d] bytes\n",parameter);
        break;
    case 32:
        printf("secp256r1 - [%d] bytes\n",parameter);
        break;
    case 48:
        printf("secp384r1 - [%d] bytes\n",parameter);
        break;
    default:
        printf("Must define ECC_CURVE to one of the available curves\n");
    }
    printf("---------------------\n");
}



