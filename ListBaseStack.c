#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ListBaseStack.h"

void StackInit(Stack * pstack)
{
	pstack->head = NULL;
}

int SIsEmpty(Stack * pstack)
{
	if(pstack->head == NULL)
		return TRUE;
	else
		return FALSE;
}

void SPush(Stack * pstack, char* data)
{
	Node * newNode = (Node*)malloc(sizeof(Node));

	strcpy(newNode->data,data);
	newNode->next = pstack->head;

	if(pstack->head != NULL)
		pstack->head->prev = newNode; 
	newNode->prev = NULL; 
	pstack->head = newNode; 

}

void data_search(Stack* pstack)
{
	if(SIsEmpty(pstack))
	{
		printf("[Error] command stack is empty!\n");
		exit(1); 
	}
	int i=1;
	pstack->cur = pstack->head;
   	printf("[Command History]\n");	
	while(pstack->cur->next != NULL)
	{
		/*
		printf("[%d]. %s\n",i,pstack->cur->data);
		i++;
	   */	
		pstack->cur = pstack->cur->next;
	   
	}
	//pstack->cur = pstack->cur->prev;
	while(pstack->cur != NULL)
	{
		printf("[%d]. %s\n",i, pstack->cur->data);
		i++;
		pstack->cur = pstack->cur->prev;
	}
}
/*
Data SPop(Stack * pstack)
{
	Data rdata;
	Node * rnode;

	if(SIsEmpty(pstack)) {
		printf("Stack Memory Error!");
		exit(-1);
	}

	rdata = pstack->head->data;
	rnode = pstack->head;

	pstack->head = pstack->head->next;
	free(rnode);

	return rdata;
}

Data SPeek(Stack * pstack)
{
	if(SIsEmpty(pstack)) {
		printf("Stack Memory Error!");
		exit(-1);
	}

	return pstack->head->data;
}
*/
