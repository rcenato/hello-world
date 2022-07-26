// Sample kernel module with producer/consumer and kernel threads.

//#include <sys/time.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/signal.h>
#include <linux/threads.h>          //signal
#include <linux/delay.h>            //ssleep()
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/kfifo.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/semaphore.h>
#include <linux/rwsem.h>
#include <linux/init.h>
//#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabio Antero de Pulpa Melo Junior");
MODULE_DESCRIPTION("AB-TRAP Concurrent Kernel Module");
MODULE_VERSION("0.11");


// Define block
#define IP_DF 0x4000
#define FIFO_SIZE 131072
#define NUM_CPU 4
#define NUM_THREADS (NUM_CPU*2)+1
#define WORKER_THREAD_DELAY 500
//#define PACKET_SIZE 1536

static struct semaphore buffer_semaphore;
//static struct rw_semaphore veredict_semaphore;
static struct task_struct *worker_task[NUM_THREADS];

static struct buffer {
  struct sk_buff *skb;
  unsigned int result;
};


static struct buffer *buffer;

static struct kfifo fifo;
static struct kfifo veredict;



// implementation of Filter callback function - Netfilter Hook
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int simpleFilter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int simpleFilter(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static unsigned int simpleFilter(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
#else
static unsigned int simpleFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#endif
{


    // Este trecho obtem o pacote da rede e o insere na fila para sr processado por uma das threads.
    if (down_interruptible(&buffer_semaphore)) { }
    //down_write(&buffer_semaphore);

	  struct buffer buffer;

          struct ethhdr *ethh;
          struct iphdr  *iph;         // ip header struct
          struct tcphdr *tcph;        // tcp header struct

          ethh = eth_hdr(skb);
          iph = ip_hdr(skb);


	  unsigned int saddr = (unsigned int)iph->saddr;
	  unsigned int daddr = (unsigned int)iph->daddr;

          printk(KERN_NOTICE "<Passo 1> Pacote com tamanho: %d: ", skb->truesize);
	  printk(KERN_NOTICE "<Passo 1> Pacote recebido do IP %pI4: ", &saddr);
          printk(KERN_NOTICE "<Passo 1> Pacote recebido para o IP %pI4: ", &daddr);

    	  buffer.skb = skb;
    	  buffer.result = 0;

    	  int sizebuff = sizeof(buffer.skb) + sizeof(buffer.result);
//          int sizebuff = sizeof(struct sk_buff) + sizeof(unsigned int);

    	  int r = kfifo_in(&fifo, &buffer, sizebuff);
    	  int size = kfifo_size(&fifo);
    	  int len = kfifo_len(&fifo);

    	  if (r == sizebuff){
		printk(KERN_INFO "Elemento com %d bytes inserido no buffer de pacotes a processar. Fila com tamanho %d de %d.", sizebuff, len, size);
   	  }else{
		printk(KERN_ERR "Elemento com %d bytes não inserido ou inserido parcialmente no buffer de pacotes a processar. Fila com tamanho %d de %d.", sizebuff, len, size);
    	  }

    up(&buffer_semaphore);


    // Este trecho obtem o pacote processado para retornar o veredito.
//    down_read(&buffer_semaphore);


    if (down_interruptible(&buffer_semaphore)) { }

          struct buffer buffer_p;

	  //int buffsize = sizeof(kfifo_peek(&veredict, &buffer));
	  int buffsize = sizeof(buffer.skb) + sizeof(buffer.result);
          //int buffsize = sizeof(struct sk_buff) + sizeof(unsigned int);
	  //int buffsize = kfifo_peek_len(&veredict);
          int rep = kfifo_out(&veredict, &buffer_p, buffsize);
          int s = kfifo_size(&veredict);
          int l = kfifo_len(&veredict);

	  int result;
    	  if (rep == buffsize){
          	printk(KERN_INFO "Elemento removido do buffer de pacotes processados. Fila com tamanho %d de %d.", l, s);
            	result = buffer_p.result;
    	  }else{
	        printk(KERN_ERR "Elemento não removido ou removido parcialmente no buffer de pacotes processados. Fila com tamanho %d de %d.", l, s);
	  }

    up(&buffer_semaphore);

//    up_read(&buffer_semaphore);

    int cpu;
    cpu = get_cpu();
    //n_cpu = num_online_cpus();
    printk(KERN_INFO "Filter executando na CPU %d de %d. \n", cpu, NUM_CPU);
    put_cpu();


//    printk(KERN_ALERT "Veredito do pacote: %d", result);

    return result;

//    return NF_ACCEPT;

}

//static struct nf_hook_ops filter_hooks[NUM_THREADS];

// Netfilter hooks
static struct nf_hook_ops simpleFilterHook = {
    .hook       = simpleFilter,
    .hooknum    = NF_INET_PRE_ROUTING,
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    .owner      = THIS_MODULE
#endif
};


static int simple_net_filter_consumer(void *args){

        int i;

	i = (int*)args;

        /*
         * Permite interromper a thread do userspace ou kernelspace.
         */
        allow_signal(SIGKILL);

        while(!kthread_should_stop()){

                printk(KERN_INFO "Thread %d produtora em execução na CPU: %d \n", i, get_cpu());

                if (down_interruptible(&buffer_semaphore)) { }

		struct buffer buffer;
//                down_read(&buffer_semaphore);

		if (!kfifo_is_empty(&fifo)){
			int result = 0;

//	                down_write(&buffer_semaphore);
//	                int buffsize = sizeof(kfifo_peek(&fifo, &buffer));
			//int buffsize = kfifo_peek_len(&fifo);
                        //printk(KERN_NOTICE "<Passo 2> Pacote com tamanho calculado: %d: ", buffsize);

                        int buffsize = sizeof(buffer.skb) + sizeof(buffer.result);
			//int buffsize = sizeof(struct sk_buff) + sizeof(unsigned int);
        	        int rep = kfifo_out(&fifo, &buffer, buffsize);
//	                up_write(&buffer_semaphore);

               		if (rep == buffsize){

                        	printk(KERN_DEBUG "Iniciando a Arvore de Decisao.\n");

				    struct buffer buffer_p;

				    int result = 0;
                                    //buffer_p.skb = buffer.skb;

				    //result = decision_tree(buffer_p);

					struct ethhdr *ethh;
    					struct iphdr  *iph;         // ip header struct
    					struct tcphdr *tcph;        // tcp header struct

    					u_int16_t tcp_segment_length; // similar to wireshark ip.len
    					//u_int8_t flags;

    					ethh = eth_hdr(buffer.skb);

    					iph = ip_hdr(buffer.skb);

			                unsigned int saddr = (unsigned int)iph->saddr;
          				unsigned int daddr = (unsigned int)iph->daddr;

          				printk(KERN_NOTICE "<Passo 2> Pacote com tamanho: %d: ", buffer.skb->truesize);
          				printk(KERN_NOTICE "<Passo 2> Pacote recebido do IP %pI4: ", &saddr);
          				printk(KERN_NOTICE "<Passo 2> Pacote recebido para o IP %pI4: ", &daddr);

    					if (!(iph)){
                				goto ACCEPT;
    					}

					if (iph->protocol == IPPROTO_TCP){ // TCP Protocol
						tcph = tcp_hdr(buffer.skb);

						//flags = ((u_int8_t *)tcph)[13];

						// tcp payload size in bytes
						tcp_segment_length = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4); 

						//if (tcph->dest == htons(22)){
						//	printk(KERN_INFO "tcp.th_flags: %d", flags); 
						//}

						// Start of Decision Tree

						if (iph->tot_len < htons(65)) {
						      if (tcph->fin == 0) {
							  if ((tcph->doff*4) < htons(38)) {
							      if ((iph->frag_off & IP_DF) == 0) {
								  if (tcph->syn == 0) {
								      if (iph->tot_len < htons(41)) {
									  if (tcph->window < htons(507)) {
									      goto ACCEPT;
									  } else {
									      if (tcph->window < htons(1300)) {
										  if (tcph->window < htons(1025)) {
										      if (iph->id < htons(58935)) {
										          if (iph->id < htons(20092)) {
										             goto DROP;
										          } else {
										             goto DROP;
										          }
										      } else {
										          if (iph->id < htons(58937)) {
										              goto ACCEPT;
										          } else {
										             goto DROP;
										          }
										      }
										  } else {
										      if (tcph->rst == 0) {
										          goto ACCEPT;
										      } else {
										          if (iph->tos < htons(4)) {
										              goto DROP;
										          } else {
										              goto ACCEPT;
										          }
										      }
										  }
									      } else {
										  if (tcph->ack == 0) {
										      goto ACCEPT;
										  } else {
										      goto ACCEPT;
										  }
									      }
									  }
								      } else {
									  if ((tcph->doff*4) < htons(26)) {
									      goto ACCEPT;
									  } else {
									      goto ACCEPT;
									  }
								      }
								  } else {
								      if (tcph->window < htons(521)) {
									  if (tcph->window < htons(507)) {
									      goto ACCEPT;
									  } else {
									      goto DROP;
									  }
								      } else {
									  if (tcph->window < htons(65524)) {
									      if (iph->tot_len < htons(42)) {
										  if (tcph->window < htons(1065)) {
										      if (iph->tos < htons(2)) {
										          if (iph->id < htons(60742)) {
										              goto ACCEPT;
										          } else {
										              goto ACCEPT;
										          }
										      } else {
										          goto ACCEPT;
										      }
										  } else {
										      goto ACCEPT;
										  }
									      } else {
										  if (tcph->window < htons(1026)) {
										      if (iph->tos < htons(4)) {
										          if (tcph->window < htons(933)) {
										              goto ACCEPT;
											  }else{
										              goto DROP;
										          }
										      } else {
										          goto ACCEPT;
										      }
										  } else {
										      goto ACCEPT;
										  }
									      }
									  } else {
									      if (iph->tos < htons(4)) {
										  if ((tcph->doff*4) < htons(22)) {
										      goto DROP;
										  } else {
										      goto ACCEPT;
										  }
									      } else {
										  goto ACCEPT;
									      }
									  }
								      }
								  }
							      } else {
								  if (tcph->window < htons(1)) {
								      if (iph->id < htons(60)) {
									  if (tcph->ack == 0) {
									      if (iph->tos < htons(1)) {
										  goto DROP;
									      } else {
										  if (iph->tos < htons(5)) {
										      goto ACCEPT;
										  } else {
										      goto ACCEPT;
										  }
									      }
									  } else {
									      if (tcph->rst == 0) {
										  goto ACCEPT;
									      } else {
										  goto ACCEPT;
									      }
									  }
								      } else {
									  if (iph->id < htons(38767)) {
									      goto ACCEPT;
									  } else {
									      if (iph->id < htons(38841)) {
										  goto DROP;
									      } else {
										  if (iph->id < htons(41467)) {
										      if (iph->id < htons(41284)) {
										          goto ACCEPT;
										      } else {
										          goto DROP;
										      }
										  } else {
										      if (iph->id < htons(60710)) {
										          if (tcph->ack == 0) {
										              goto ACCEPT;
										          } else {
										              goto ACCEPT;
										          }
										      } else {
										          if (iph->id < htons(60827)) {
										              goto DROP;
										          } else {
										              goto ACCEPT;
										          }
										      }
										  }
									      }
									  }
								      }
								  } else {
								      if ((unsigned int)tcp_segment_length < 19) {
									  if (tcph->window < htons(28944)) {
									      goto ACCEPT;
									  } else {
									      if (tcph->window < htons(29008)) {
										  if (iph->id < htons(26421)) {
										      goto ACCEPT;
										  } else {
										      goto DROP;
										  }
									      } else {
										  if (tcph->rst == 0) {
										      if (iph->id < htons(51143)) {
										          goto ACCEPT;
										      } else {
										          if (iph->id < htons(51161)) {
										              goto DROP;
										          } else {
										              goto ACCEPT;
										          }
										      }
										  } else {
										      if (iph->tot_len < htons(46)) {
										          goto ACCEPT;
										      } else {
										          goto DROP;
										      }
										  }
									      }
									  }
								      } else {
									  if (tcph->window < htons(21780)) {
									      goto ACCEPT;
									  } else {
									      if (tcph->window < htons(46454)) {
										  goto DROP;
									      } else {
										  goto ACCEPT;
									      }
									  }
								      }
								  }
							      }
							  } else {
							      if (tcph->window < htons(15749)) {
								  goto ACCEPT;
							      } else {
								  if (tcph->window < htons(64520)) {
								      if (iph->id < htons(11)) {
									  goto ACCEPT;
								      } else {
									  if (tcph->window < htons(16472)) {
									      if ((tcph->doff*4) < htons(42)) {
										  goto ACCEPT;
									      } else {
										  goto DROP;
									      }
									  } else {
									      if (tcph->window < htons(64157)) {
										  goto ACCEPT;
									      } else {
										  if (iph->id < htons(55527)) {
										      if (iph->id < htons(55380)) {
										          if (iph->id < htons(50700)) {
										              goto DROP;
										          } else {
										              goto DROP;
										          }
										      } else {
										          goto DROP;
										      }
										  } else {
										      goto DROP;
										  }
									      }
									  }
								      }
								  } else {
								      if ((iph->frag_off & IP_DF) == 0) {
									  goto ACCEPT;
								      } else {
									  goto ACCEPT;
								      }
								  }
							      }
							  }
						      } else {
							  if (tcph->window < htons(512)) {
							      goto ACCEPT;
							  } else {
							      if (iph->id < htons(2)) {
								  goto ACCEPT;
							      } else {
								  if (tcph->window < htons(16498)) {
								      if (iph->tos < htons(4)) {
									  if (tcph->ack == 0) {
									      if (tcph->psh == 0) {
										  goto DROP;
									      } else {
										  goto DROP;
									      }
									  } else {
									      if (tcph->window < htons(1024)) {
										  goto ACCEPT;
									      } else {
										  if (tcph->window < htons(15616)) {
										      if (tcph->window < htons(1025)) {
										          if ((iph->frag_off & IP_DF) == 0) {
										              goto DROP;
										          } else {
										              goto ACCEPT;
										          }
										      } else {
										          goto ACCEPT;
										      }
										  } else {
										      goto DROP;
										  }
									      }
									  }
								      } else {
									  goto ACCEPT;
								      }
								  } else {
								      goto ACCEPT;
								  }
							      }
							  }
						      }
						  } else {
						      if (iph->id < htons(1)) {
							  goto ACCEPT;
						      } else {
							  goto ACCEPT;
						      }
						  }


						}

				    ACCEPT:
				    	buffer_p.result = NF_ACCEPT;
                                        printk(KERN_NOTICE "<Passo 3> Pacote aceito.");
					goto DONE;

				    DROP:
				    	buffer_p.result = NF_DROP;
 	                                printk(KERN_NOTICE "<Passo 3> Pacote dropado.");
					goto DONE;


				    DONE:

				    buffer_p.skb = buffer.skb;

//                                    down_write(&buffer_semaphore);

    					    int sizebuff = sizeof(buffer_p.skb) + sizeof(buffer_p.result);
					    //int sizebuff = buffer.skb->truesize;
		                            //int sizebuff = sizeof(struct sk_buff) + sizeof(unsigned int);
					    //int sizebuff = sizeof(buffer_p);
    					    int r = kfifo_in(&veredict, &buffer_p, sizebuff);
    					    int size = kfifo_size(&veredict);
    					    int len = kfifo_len(&veredict);

					    if (r == sizebuff){
        					printk(KERN_INFO "Elemento inserido no buffer de pacotes processados. Fila com tamanho %d de %d.", len, size);
    					    }else{
        					printk(KERN_ERR "Elemento não inserido ou inserido parcialmente no buffer de pacotes processados. Fila com tamanho %d de %d.", len, size);
    					    }

//		                    up_write(&buffer_semaphore);


    				printk(KERN_DEBUG "Finalizando a Arvore de Decisao.\n");

                	}else{

                        	printk(KERN_ERR "Elemento não removido do buffer ou removido parcialmente.");

                	}

		}

                up(&buffer_semaphore);

                msleep(WORKER_THREAD_DELAY);

                if (signal_pending(worker_task[i]))
                        break;
        }

        do_exit(0);

        printk(KERN_INFO "Thread produtora sendo encerrada.\n");

        return 0;
}



int __init kernel_thread_init(void){


	sema_init(&buffer_semaphore, 1);
//	init_rwsem(&buffer_semaphore);
//	init_rwsem(&veredict_semaphore);

	int ret = 0;
	ret = kfifo_alloc(&fifo, FIFO_SIZE, GFP_KERNEL);
	if (ret == 0){
	        //kfifo_init(&fifo, &buffer, FIFO_SIZE);
	        printk(KERN_INFO "Buffer de pacotes a processar criado com sucesso.\n");
	}else{
                printk(KERN_ERR "Erro na criação do buffer de pacotes a processar. Código de erro: %d \n", ret);
	}

        ret = kfifo_alloc(&veredict, FIFO_SIZE, GFP_KERNEL);
        if (ret == 0){
                //kfifo_init(&veredict, &buffer, FIFO_SIZE);
                printk(KERN_INFO "Buffer de pacotes processados criado com sucesso.\n");
        }else{
                printk(KERN_ERR "Erro na criação do buffer de pacotes processados. Código de erro: %d \n", ret);
        }


	int i;

        #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
                nf_register_hook(&simpleFilterHook);
        #else
                nf_register_net_hook(&init_net, &simpleFilterHook);
        #endif

	printk(KERN_INFO "Inicializando módulo de kernel.\n");
	printk(KERN_INFO "Criando as Threads.\n");


	for (i = 1; i<=NUM_THREADS; i++){
		//char* thread_name = strcat("NF_Consumer_", i);
        	worker_task[i] = kthread_create(simple_net_filter_consumer, (void*)i, "NF_Consumer");
        	kthread_bind(worker_task[i], (i > 12 ? i : i%2));
        	if(worker_task[i]){
                	printk(KERN_INFO "Thread produtora %d criada com sucesso.\n", i);
                	wake_up_process(worker_task[i]);
        	}else{
                	printk(KERN_INFO "Thread produtora não criada. Ocorreu um erro durante a criação da thread.\n");
        	}
	}


	return 0;
}

void __exit kernel_thread_exit(void){


        #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
                nf_register_hook(&simpleFilterHook);
        #else
                nf_unregister_net_hook(&init_net, &simpleFilterHook);
        #endif

        kfifo_free(&fifo);
	kfifo_free(&veredict);

	printk(KERN_INFO "Módulos sendo removidos do kernel, threads sendo paradas.\n");

	/*@brief
	 * this functions will send SIGKILL's to stop threads when module removing
	*/
	int i;
        for (i=1; i<=NUM_THREADS; i++){
		if(worker_task[i])
			kthread_stop(worker_task[i]);
	}

	printk(KERN_INFO "Threads consumidoras paradas. \n");

	printk(KERN_INFO "Fim.\n");

}

module_init(kernel_thread_init);
module_exit(kernel_thread_exit);
