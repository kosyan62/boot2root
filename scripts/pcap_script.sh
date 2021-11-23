for f in `grep file ./* | sort -nk2 -t 'e' | cut -f 2 -d '/' | cut -f 1 -d ':'`
	do sed 's/\/\/file[0-9]\+//' $f >> code
done

