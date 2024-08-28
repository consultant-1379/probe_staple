#!/bin/bash


if [ "$2" == "" ]; then
	echo usage: $0 \<Module\> \<Branch\> \<Workspace\>
    	exit -1
else
	versionProperties=install/version.properties
	theDate=\#$(date +"%c")
	module=$1
	branch=$2
	workspace=$3
	pkgDir=$workspace/packages
	rpmFileLocation=${workspace}/target/rpm/ERICstaple-CXC1734186/RPMS/x86_64
	pkgReleaseArea=/home/jkadm100/eniq_events_releases
	
fi

function getProductNumber {
        product=`cat $workspace/build.cfg | grep $module | grep $branch | awk -F " " '{print $3}'`
}


function setRstate {
        revision=`cat $workspace/build.cfg | grep $module | grep $branch | awk -F " " '{print $4}'`

        if git tag | grep $product-$revision; then
		rstate=`git tag | grep ${product}-${revision} | tail -1 | sed s/.*-// | perl -nle 'sub nxt{$_=shift;$l=length$_;sprintf"%0${l}d",++$_}print $1.nxt($2) if/^(.*?)(\d+$)/';`
        else
                ammendment_level=01
		rstate=$revision$ammendment_level
	fi
}


function cleanup {
        if [ -d $pkgDir ] ; then
          echo "removing $pkgDir"
          rm -rf $pkgDir
        fi
}

function createTar {
    echo "Copying $rpmFile into $pkgDir"
    cp $rpmFile $pkgDir
    cd $workspace
    tar -czvf $workspace/$pkgName packages/
    echo "Copying tar file into $pkgReleaseArea"
    cp $workspace/$pkgName $pkgReleaseArea
}


function runMaven {
    mvn -f $workspace/pom.xml clean package -Drstate=$rstate 
    rsp=$?
}

cleanup
getProductNumber
setRstate
pkgName="staple_${rstate}.tar.gz"
git clean -df
git checkout $branch
git pull

runMaven

mkdir $pkgDir


if [ $rsp == 0 ]; then
  git tag $product-$rstate
  git pull
  git push --tag origin $branch

  rpm=`ls $rpmFileLocation`
  echo "RPM built:$rpm"
  rpmFile=$rpmFileLocation/$rpm
  echo "Creating tar file..."
  createTar
  touch $workspace/rstate.txt
  echo $rstate >> $workspace/rstate.txt

fi  

exit $rsp
