#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/poll.h>

#define GLOBALFIFO_SIZE	0x1000
#define MEM_CLEAR 0x1
#define GLOBALFIFO_MAJOR	230

static int globalfifo_major = GLOBALFIFO_MAJOR;
module_param(globalfifo_major, int, S_IRUGO);

struct globalfifo_dev {
	struct cdev cdev;
	unsigned int current_len;
	unsigned char mem[GLOBALFIFO_SIZE];
	struct mutex mutex;
	wait_queue_head_t r_wait;
	wait_queue_head_t w_wait;
};

struct globalfifo_dev *globalfifo_devp;

static int globalfifo_open(struct inode *inode, struct file *filp)
{
	filp->private_data = globalfifo_devp;
	return 0;
}

static int globalfifo_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t globalfifo_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	struct globalfifo_dev *dev = filp->private_data;
	switch(cmd) {
		case MEM_CLEAR:
			mutex_lock(&dev->mutex);
			memset(dev->mem, 0, GLOBALFIFO_SIZE);
			mutex_unlock(&dev->mutex);
			pr_info("globalfifo is set to 0\n");
			break;

		default:
			return -EINVAL;
	}
	return 0;
}

static ssize_t globalfifo_read(struct file *filp, char __user *buf, size_t size,
			  loff_t * ppos)
{
	unsigned long p = *ppos;
	unsigned int count = size;
	int ret = 0;
	struct globalfifo_dev *dev = filp->private_data;
	DECLARE_WAITQUEUE(wait, current);

	if (p >= GLOBALFIFO_SIZE) {
		return 0;
	}
	if (count >= GLOBALFIFO_SIZE - p) {
		count = GLOBALFIFO_SIZE - p;
	}

	mutex_lock(&dev->mutex);
	add_wait_queue(&dev->r_wait, &wait);
	while (dev->current_len == 0) {
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		__set_current_state(TASK_INTERRUPTIBLE);
		mutex_unlock(&dev->mutex);

		schedule();
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto out2;
		}

		mutex_lock(&dev->mutex);
	}
	if (count >= dev->current_len) 
		count = dev->current_len;

	if (!copy_to_user(buf, dev->mem + p, count)) {
		memcpy(dev->mem, dev->mem + count, dev->current_len - count);
		dev->current_len -= count;
		pr_info("read %d bytes, current_len: %d\n", count, dev->current_len);
		wake_up_interruptible(&dev->w_wait);

		ret = count;

	} else {
		ret = -EFAULT;
		goto out;
	}

out:
	mutex_unlock(&dev->mutex);
out2:
	remove_wait_queue(&dev->r_wait, &wait);
	set_current_state(TASK_RUNNING);

	return ret;
}

static ssize_t globalfifo_write(struct file *filp, const char __user * buf, size_t size,
			   loff_t * ppos)
{
	unsigned long p = *ppos;
	unsigned int count = size;
	int ret = 0;
	struct globalfifo_dev *dev = filp->private_data;
	DECLARE_WAITQUEUE(wait, current);

	if (p >= GLOBALFIFO_SIZE)
		return 0;
	if (count >= GLOBALFIFO_SIZE - p) {
		count = GLOBALFIFO_SIZE - p;
	}

	mutex_lock(&dev->mutex);
	add_wait_queue(&dev->w_wait, &wait);
	while (dev->current_len == GLOBALFIFO_SIZE) {
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		__set_current_state(TASK_INTERRUPTIBLE);

		mutex_unlock(&dev->mutex);

		schedule();
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto out2;
		}
		
		mutex_lock(&dev->mutex);
	}
	if (count > GLOBALFIFO_SIZE - dev->current_len)
		count = GLOBALFIFO_SIZE - dev->current_len;
	
	if (!copy_from_user(dev->mem + p, buf, count)) {
		dev->current_len += count;
		pr_info("write %d bytes, current_len: %d\n", count, dev->current_len);

		wake_up_interruptible(&dev->r_wait);
		ret = count;

	} else {
		ret = -EFAULT;
		goto out;
	}

out:
	mutex_unlock(&dev->mutex);
out2:
	remove_wait_queue(&dev->w_wait, &wait);
	set_current_state(TASK_RUNNING);

	return ret;
}

static loff_t globalfifo_llseek(struct file *filp, loff_t offset, int orig)
{
	loff_t ret = 0;
	switch (orig) {
		case 0:
			if (offset < 0) {
				ret = -EINVAL;
				break;
			}
			if ((unsigned int) offset > GLOBALFIFO_SIZE) {
				ret = -EINVAL;
				break;
			}
			filp->f_pos = (unsigned int)offset;
			ret = filp->f_pos;
			break;
		case 1:
			if ((filp->f_pos + offset) > GLOBALFIFO_SIZE) {
				ret = -EINVAL;
				break;
			}
			if ((filp->f_pos + offset) < 0) {
				ret = -EINVAL;
				break;
			}
			filp->f_pos += offset;
			ret = filp->f_pos;
			break;
		default:
			ret = -EINVAL;
			break;
	}
	return ret;
}

static unsigned int globalfifo_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	struct globalfifo_dev *dev = filp->private_data;

	mutex_lock(&dev->mutex);
	poll_wait(filp, &dev->r_wait, wait);
	poll_wait(filp, &dev->w_wait, wait);

	if (dev->current_len != 0) {
		mask |= POLLIN | POLLRDNORM;
	}

	if (dev->current_len != GLOBALFIFO_SIZE) {
		mask |= POLLOUT | POLLWRNORM;
	}

	mutex_unlock(&dev->mutex);
	return mask;
}

static const struct file_operations globalfifo_fops = {
	.owner = THIS_MODULE,
	.llseek = globalfifo_llseek,
	.read = globalfifo_read,
	.write = globalfifo_write,
	.unlocked_ioctl = globalfifo_ioctl,
	.open = globalfifo_open,
	.release = globalfifo_release,
	.poll = globalfifo_poll,
};

static void globalfifo_setup_cdev(struct globalfifo_dev *dev, int index)
{
	int err;
	int devno = MKDEV(globalfifo_major, index);

	printk("hello\n");

	cdev_init(&dev->cdev, &globalfifo_fops);
	err = cdev_add(&dev->cdev, devno, 1);
	if (err)
		printk(KERN_NOTICE "Error %d adding globalfifo %d\n", err, index);
}

static int __init globalfifo_init(void)
{
	int ret;
	dev_t devno = MKDEV(globalfifo_major, 0);

	if (globalfifo_major)
		ret = register_chrdev_region(devno, 1, "globalfifo");
	else {
		ret = alloc_chrdev_region(&devno, 0, 1, "globalfifo");
		globalfifo_major = MAJOR(devno);
	}
	if (ret < 0)
		return ret;
	
	globalfifo_devp = kzalloc(sizeof(struct globalfifo_dev), GFP_KERNEL);
	if (!globalfifo_devp) {
		ret = -ENOMEM;
		goto fail_malloc;
	}

	mutex_init(&globalfifo_devp->mutex);
	globalfifo_setup_cdev(globalfifo_devp, 0);
	
	init_waitqueue_head(&globalfifo_devp->r_wait);
	init_waitqueue_head(&globalfifo_devp->w_wait);
	return 0;

fail_malloc:
	unregister_chrdev_region(devno, 1);
	return ret;
}
module_init(globalfifo_init);

static void __exit globalfifo_exit(void)
{
	cdev_del(&globalfifo_devp->cdev);
	kfree(globalfifo_devp);
	unregister_chrdev_region(MKDEV(globalfifo_major, 0), 1);
}
module_exit(globalfifo_exit);

MODULE_AUTHOR("fywc");
MODULE_LICENSE("GPL v2");





