export const makeQueue = () => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	let task = Promise.resolve() as Promise<any>

	return {
		enqueue<A extends any[], R, T extends(...args: A) => R>(code: T, ...args: A): Promise<R> {
			task = (async() => {
				// wait for the previous task to complete
				// if there is an error, we swallow so as to not block the queue
				try {
					await task
				} catch{ }

				// execute the current task
				const result = await code(...args)
				return result
			})()
			// we replace the existing task, appending the new piece of execution to it
			// so the next task will have to wait for this one to finish
			return task
		},
	}
}